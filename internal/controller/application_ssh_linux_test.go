//go:build linux

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"portico.local/portico/internal/agent"
)

func sshApplicationKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	block, err := ssh.MarshalPrivateKey(key, "isolated Portico SSH fixture")
	must(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	must(t, err)
	return signer, pem.EncodeToMemory(block)
}

// This test runs real OpenSSH and Portico CLI processes, encrypted enrollment,
// the restricted issuer, daemon, controller and connector. The destination is
// a real SSH protocol server with independent host-key and user-key checks.
func TestArchGuestApplicationSSH(t *testing.T) {
	requireArchApplicationGuest(t)
	if os.Getenv("PORTICO_SSH_FIXTURE") != "1" {
		t.Skip("requires the signature-verified Arch OpenSSH fixture")
	}
	versionContext, cancelVersion := context.WithTimeout(ctx, 10*time.Second)
	defer cancelVersion()
	version, err := exec.CommandContext(versionContext, "/usr/bin/ssh", "-V").CombinedOutput()
	must(t, err)
	if !strings.HasPrefix(string(version), "OpenSSH_10.5p1,") {
		t.Fatal("unexpected Arch OpenSSH version")
	}
	t.Log(strings.TrimSpace(string(version)))
	networkBefore := applicationNetworkSnapshot(t)
	hostKey, hostPrivate := sshApplicationKey(t)
	defer clear(hostPrivate)
	userKey, userPrivate := sshApplicationKey(t)
	defer clear(userPrivate)
	otherKey, otherPrivate := sshApplicationKey(t)
	defer clear(otherPrivate)
	request := bytes.Repeat([]byte{'s', 's', 'h', 0, 0xff, '\n'}, 64)
	response := append(bytes.Repeat([]byte{'r', 'e', 's', 0, 0xfe, '\n'}, 1024), request...)
	var authenticated, commands atomic.Int64
	var protocolInvalid atomic.Bool
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "alice" || !bytes.Equal(key.Marshal(), userKey.PublicKey().Marshal()) {
			return nil, errors.New("fixture SSH identity rejected")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(hostKey)
	destination := func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		connection, channels, globals, err := ssh.NewServerConn(c, config)
		if err != nil {
			return // Untrusted host keys and wrong user keys must not authenticate.
		}
		authenticated.Add(1)
		globalsDone := make(chan struct{})
		go func() { ssh.DiscardRequests(globals); close(globalsDone) }()
		defer func() { _ = connection.Close(); <-globalsDone }()
		opened := 0
		for pending := range channels {
			opened++
			if opened != 1 || pending.ChannelType() != "session" {
				protocolInvalid.Store(true)
				_ = pending.Reject(ssh.Prohibited, "fixture expects one session")
				return
			}
			channel, requests, err := pending.Accept()
			if err != nil {
				protocolInvalid.Store(true)
				return
			}
			defer channel.Close()
			executed := false
			for r := range requests {
				var command struct{ Command string }
				if executed || r.Type != "exec" || ssh.Unmarshal(r.Payload, &command) != nil || (command.Command != "fixture-success" && command.Command != "fixture-failure" && command.Command != "fixture-hold" && command.Command != "-G") {
					protocolInvalid.Store(true)
					_ = r.Reply(false, nil)
					return
				}
				executed = true
				commands.Add(1)
				if r.Reply(true, nil) != nil {
					protocolInvalid.Store(true)
					return
				}
				if command.Command == "fixture-hold" {
					if _, err := channel.Write([]byte("SSH-HOLD-READY\n")); err != nil {
						protocolInvalid.Store(true)
						return
					}
					// Keep the authenticated SSH session open until outer Portico
					// revocation closes it. No remote exit status ends this case.
					_, _ = io.Copy(io.Discard, channel)
					return
				}
				input, err := io.ReadAll(io.LimitReader(channel, int64(len(request)+1)))
				if err != nil || !bytes.Equal(input, request) {
					protocolInvalid.Store(true)
					return
				}
				if _, err := channel.Write(response); err != nil {
					protocolInvalid.Store(true)
					return
				}
				status := uint32(0)
				if command.Command == "fixture-failure" {
					status = 17
				}
				if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status})); err != nil {
					protocolInvalid.Store(true)
					return
				}
				_ = channel.CloseWrite()
				_ = channel.Close()
				// Wait for OpenSSH's transport close so the server exercises both
				// directions of the outer Portico stream's completion protocol.
				_ = connection.Wait()
				return
			}
		}
	}
	session := newApplicationSession(t, destination)
	v, write := session.v, session.write
	f := v.carrier.policy.device.f
	identity := write("SSH user key", userPrivate)
	wrongIdentity := write("other SSH user key", otherPrivate)
	trust := write("known SSH hosts", append([]byte("ssh.private.test "), ssh.MarshalAuthorizedKey(hostKey.PublicKey())...))
	wrongTrust := write("wrong SSH hosts", append([]byte("ssh.private.test "), ssh.MarshalAuthorizedKey(otherKey.PublicKey())...))
	emptyTrust := write("empty SSH hosts", nil)
	// An actual ambient agent can authenticate this account. The selected
	// identity must still be exclusive; a wrong key must not fall back to it.
	ring := sshagent.NewKeyring()
	rawUserKey, err := ssh.ParseRawPrivateKey(userPrivate)
	must(t, err)
	must(t, ring.Add(sshagent.AddedKey{PrivateKey: rawUserKey}))
	agentPath := filepath.Join(session.dir, "ambient-agent.sock")
	agentListener, err := net.Listen("unix", agentPath)
	must(t, err)
	var agentConnections atomic.Int64
	var agentWorkers sync.WaitGroup
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			c, err := agentListener.Accept()
			if err != nil {
				return
			}
			agentConnections.Add(1)
			agentWorkers.Go(func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				_ = sshagent.ServeAgent(ring, c)
			})
		}
	}()
	t.Cleanup(func() { _ = agentListener.Close(); <-agentDone; agentWorkers.Wait() })
	probe, err := net.Dial("unix", agentPath)
	must(t, err)
	must(t, probe.SetDeadline(time.Now().Add(5*time.Second)))
	keys, err := sshagent.NewClient(probe).List()
	must(t, err)
	must(t, probe.Close())
	if len(keys) != 1 || agentConnections.Load() != 1 {
		t.Fatal("ambient agent positive control failed")
	}
	t.Setenv("SSH_AUTH_SOCK", agentPath)
	// These locations belong only to the disposable root guest. Do not replace
	// existing entries, even in a fixture. The invalid config detects accidental
	// configuration loading; default trust/key files detect authentication fallback.
	for path, data := range map[string][]byte{
		"/root/.ssh/config":        []byte("PorticoInvalidFixtureOption yes\n"),
		"/root/.ssh/id_ed25519":    userPrivate,
		"/etc/ssh/ssh_known_hosts": append([]byte("ssh.private.test "), ssh.MarshalAuthorizedKey(hostKey.PublicKey())...),
	} {
		must(t, os.MkdirAll(filepath.Dir(path), 0700))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		must(t, err)
		_, err = file.Write(data)
		must(t, err)
		must(t, file.Close())
		t.Cleanup(func() { must(t, os.Remove(path)) })
	}
	trustBefore, err := os.ReadFile(trust)
	must(t, err)
	type sshCase struct {
		name, host, user, trust, identity, resource, command string
		revision                                             int64
		success, output                                      bool
		connections, authentications, executions             int64
	}
	positive := sshCase{"authenticated_ssh", "ssh.private.test", "alice", trust, identity, v.resource.ID, "fixture-success", v.resource.Revision, true, true, 1, 1, 1}
	check := func(t *testing.T, test sshCase) {
		t.Helper()
		before, beforeAuth, beforeCommands := v.connections.Load(), authenticated.Load(), commands.Load()
		var beforeSessions, afterSessions int64
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&beforeSessions))
		endpointDir, err := os.MkdirTemp(session.dir, "ssh % $(false) ; ")
		must(t, err)
		t.Cleanup(func() { must(t, os.RemoveAll(endpointDir)) })
		endpoint := filepath.Join(endpointDir, "application.sock")
		if test.connections != 0 {
			session.bindFresh(t)
		}
		args := []string{"agent", "ssh", "--socket", session.socket, "--resource", test.resource, "--revision", strconv.FormatInt(test.revision, 10), "--endpoint", endpoint, "--host", test.host, "--user", test.user, "--known-hosts", test.trust, "--identity", test.identity, "--", test.command}
		p := guestStartApplication(t, args...)
		if test.output {
			must(t, p.input.SetWriteDeadline(time.Now().Add(5*time.Second)))
			_, err = p.input.Write(request)
			must(t, err)
		}
		must(t, p.input.Close())
		must(t, p.output.SetReadDeadline(time.Now().Add(25*time.Second)))
		output, err := io.ReadAll(io.LimitReader(p.output, int64(len(response)+1)))
		must(t, err)
		select {
		case <-p.done:
			if (p.err == nil) != test.success {
				t.Fatalf("SSH launcher exit=%v; stderr=%q", p.err, p.logs.String())
			}
			if !test.success && !strings.Contains(p.logs.String(), "Local SSH application failed.\n") {
				t.Fatal("SSH process failure was not propagated by the launcher")
			}
		case <-time.After(6 * time.Second):
			t.Fatal("SSH launcher did not join after application EOF")
		}
		if (test.output && !bytes.Equal(output, response)) || (!test.output && len(output) != 0) {
			t.Fatal("SSH returned unexpected application bytes")
		}
		carrierEventually(t, func() bool { return v.closed.Load() == v.connections.Load() })
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&afterSessions))
		if v.connections.Load()-before != test.connections || authenticated.Load()-beforeAuth != test.authentications || commands.Load()-beforeCommands != test.executions || protocolInvalid.Load() {
			t.Fatalf("SSH destination/authentication/command deltas=%d/%d/%d, expected=%d/%d/%d; protocol invalid=%t", v.connections.Load()-before, authenticated.Load()-beforeAuth, commands.Load()-beforeCommands, test.connections, test.authentications, test.executions, protocolInvalid.Load())
		}
		if afterSessions-beforeSessions != test.connections {
			t.Fatal("SSH resource authority count differs from destination observations")
		}
		if _, err := os.Lstat(endpoint); !os.IsNotExist(err) {
			t.Fatal("SSH launcher retained its endpoint")
		}
	}
	t.Run(positive.name, func(t *testing.T) { check(t, positive) })
	for name, change := range map[string]func(*sshCase){
		"wrong_host_key":       func(c *sshCase) { c.trust = wrongTrust },
		"unknown_host_key":     func(c *sshCase) { c.trust = emptyTrust },
		"missing_trust_file":   func(c *sshCase) { c.trust = filepath.Join(session.dir, "missing-trust") },
		"wrong_host_name":      func(c *sshCase) { c.host = "wrong.private.test" },
		"wrong_ssh_user_key":   func(c *sshCase) { c.identity = wrongIdentity },
		"missing_ssh_user_key": func(c *sshCase) { c.identity = filepath.Join(session.dir, "missing-identity") },
		"wrong_ssh_account":    func(c *sshCase) { c.user = "bob" },
		"wrong_revision":       func(c *sshCase) { c.revision++; c.connections = 0 },
		"ungranted_resource":   func(c *sshCase) { c.resource = NewID(); c.connections = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := positive
			candidate.success, candidate.output, candidate.authentications, candidate.executions = false, false, 0, 0
			change(&candidate)
			check(t, candidate)
		})
	}
	t.Run("remote_nonzero_exit_is_failure", func(t *testing.T) {
		candidate := positive
		candidate.command, candidate.success = "fixture-failure", false
		check(t, candidate)
	})
	t.Run("remote_option_spelling_is_not_local_option", func(t *testing.T) { candidate := positive; candidate.command = "-G"; check(t, candidate) })
	t.Run("explicit_lock_prevents_new_destination", func(t *testing.T) {
		must(t, agent.Lock(ctx, session.socket))
		candidate := positive
		candidate.success, candidate.output, candidate.connections, candidate.authentications, candidate.executions = false, false, 0, 0, 0
		check(t, candidate)
	})
	session.unlock(t)
	t.Run("fresh_ssh_after_reunlock", func(t *testing.T) { check(t, positive) })
	t.Run("revocation_ends_authenticated_ssh_and_fails_launcher", func(t *testing.T) {
		session.bindFresh(t)
		endpoint := filepath.Join(session.dir, "active-ssh.sock")
		p := guestStartApplication(t, "agent", "ssh", "--socket", session.socket, "--resource", v.resource.ID, "--revision", strconv.FormatInt(v.resource.Revision, 10), "--endpoint", endpoint, "--host", "ssh.private.test", "--user", "alice", "--known-hosts", trust, "--identity", identity, "--", "fixture-hold")
		must(t, p.output.SetReadDeadline(time.Now().Add(15*time.Second)))
		marker := make([]byte, len("SSH-HOLD-READY\n"))
		_, err := io.ReadFull(p.output, marker)
		must(t, err)
		if string(marker) != "SSH-HOLD-READY\n" {
			t.Fatal("SSH did not reach authenticated remote command")
		}
		// Stdin remains open. Only revocation should terminate this session.
		must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(session.invitation) }))
		must(t, p.output.SetReadDeadline(time.Now().Add(8*time.Second)))
		trailing, err := io.ReadAll(io.LimitReader(p.output, 1024))
		must(t, err)
		if len(trailing) != 0 {
			t.Fatal("revoked SSH session returned unexpected data")
		}
		select {
		case <-p.done:
			if p.err == nil || !strings.Contains(p.logs.String(), "Local SSH application failed.\n") {
				t.Fatal("revoked SSH stream reported success")
			}
		case <-time.After(6 * time.Second):
			t.Fatal("revoked SSH launcher retained its child")
		}
		must(t, p.input.Close())
		carrierEventually(t, func() bool { return v.closed.Load() == v.connections.Load() })
		if _, err := os.Lstat(endpoint); !os.IsNotExist(err) {
			t.Fatal("revoked SSH endpoint retained")
		}
	})
	t.Run("revoked_enrollment_prevents_new_destination", func(t *testing.T) {
		candidate := positive
		candidate.success, candidate.output, candidate.connections, candidate.authentications, candidate.executions = false, false, 0, 0, 0
		check(t, candidate)
	})
	session.finish(t)
	t.Run("ssh_trust_identity_and_network_unchanged", func(t *testing.T) {
		if agentConnections.Load() != 1 {
			t.Fatal("SSH consulted ambient authentication agent")
		}
		for path, expected := range map[string][]byte{trust: trustBefore, identity: userPrivate, emptyTrust: nil} {
			retained, err := os.ReadFile(path)
			must(t, err)
			if !bytes.Equal(retained, expected) {
				t.Fatal("SSH modified provisioned trust or identity")
			}
		}
		for name, state := range applicationNetworkSnapshot(t) {
			if networkBefore[name] != state {
				t.Errorf("SSH workflow changed guest network setting: %s", name)
			}
		}
	})
}
