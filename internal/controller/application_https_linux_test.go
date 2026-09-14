//go:build linux

package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/testfixture"
)

func requireArchApplicationGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("PORTICO_SYSTEMD_FIXTURE") != "1" {
		t.Skip("requires dedicated NIC-less Arch application guest")
	}
	requireWorkloadGuest(t)
	marker, err := os.ReadFile("/portico-systemd-isolated-fixture")
	must(t, err)
	if os.Geteuid() != 0 || string(marker) != "192.0.2.10\n" {
		t.Fatal("not the disposable Arch application fixture")
	}
	for _, path := range []string{"/usr/bin/curl", "/usr/bin/openssl", "/portico-issuer"} {
		st, err := os.Stat(path)
		must(t, err)
		if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			t.Fatal("application fixture executable unavailable")
		}
	}
}

// Real curl, the encrypted enrollment/agent commands, controller, restricted
// issuer process and connector execute in one NIC-less Arch guest. Application
// TLS and HTTP authentication remain independent of Portico authorization.
func TestArchGuestApplicationHTTPS(t *testing.T) {
	requireArchApplicationGuest(t)
	networkBefore := applicationNetworkSnapshot(t)
	versionContext, stopVersion := context.WithTimeout(ctx, 5*time.Second)
	defer stopVersion()
	version, err := exec.CommandContext(versionContext, "/usr/bin/curl", "--version").Output()
	must(t, err)
	if !strings.HasPrefix(string(version), "curl 8.22.0 ") {
		t.Fatal("unexpected curl version from pinned Arch image")
	}
	t.Log(strings.Split(string(version), "\n")[0])
	appRoot, appKey := testfixture.Root(t)
	appIdentity := testfixture.TLSIdentity(t, appRoot, appKey, true)
	payload := bytes.Repeat([]byte{'a', 'p', 'p', 0, 0xff, '\n'}, 1024)
	applicationSecret := NewID()
	var requests, authenticated atomic.Int64
	var metadataInvalid atomic.Bool
	var shutdownInvalid atomic.Bool
	destination := func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		secure := tls.Server(c, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{appIdentity}})
		defer secure.Close()
		request, err := http.ReadRequest(bufio.NewReader(secure))
		if err != nil {
			return // Wrong hostname/root must fail before application HTTP.
		}
		defer request.Body.Close()
		requests.Add(1)
		if secure.ConnectionState().ServerName != "localhost" || request.Host != "localhost" || request.Method != "GET" || request.URL.Path != "/media" {
			metadataInvalid.Store(true)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+applicationSecret {
			_, _ = io.WriteString(secure, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		authenticated.Add(1)
		_, _ = fmt.Fprintf(secure, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))
		_, _ = secure.Write(payload)
		// Keep the positive destination open through both TLS close-notify
		// and the client's TCP FIN. Closing it immediately after the response
		// can reset the connector's final write/half-close. Those failures
		// remain failures; the positive fixture must finish both directions.
		if secure.CloseWrite() != nil {
			shutdownInvalid.Store(true)
			return
		}
		var trailing [1]byte
		if n, err := secure.Read(trailing[:]); n != 0 || err != io.EOF {
			shutdownInvalid.Store(true)
			return
		}
		if n, err := c.Read(trailing[:]); n != 0 || err != io.EOF {
			shutdownInvalid.Store(true)
		}
	}
	session := newApplicationSession(t, destination)
	v := session.v
	f := v.carrier.policy.device.f
	dir, socket, write := session.dir, session.socket, session.write
	bindOnCatalog, invitation := session.bindOnCatalog, session.invitation
	rootFile := write("application-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: appRoot.Raw}))
	otherRoot, _ := testfixture.Root(t)
	otherRootFile := write("untrusted-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherRoot.Raw}))
	headers := write("application-headers", []byte("Authorization: Bearer "+applicationSecret+"\n"))
	type curlCase struct {
		name, host, trust, id string
		revision              int64
		auth, success         bool
		connections, http     int64
	}
	cases := []curlCase{
		{"authenticated_https", "localhost", rootFile, v.resource.ID, v.resource.Revision, true, true, 1, 1},
		{"wrong_hostname", "wrong.test", rootFile, v.resource.ID, v.resource.Revision, true, false, 1, 0},
		{"untrusted_certificate", "localhost", otherRootFile, v.resource.ID, v.resource.Revision, true, false, 1, 0},
		{"missing_application_authentication", "localhost", rootFile, v.resource.ID, v.resource.Revision, false, false, 1, 1},
		{"wrong_resource_revision", "localhost", rootFile, v.resource.ID, v.resource.Revision + 1, true, false, 0, 0},
		{"ungranted_resource", "localhost", rootFile, NewID(), 1, true, false, 0, 0},
		{"positive_control_after_denials", "localhost", rootFile, v.resource.ID, v.resource.Revision, true, true, 1, 1},
	}
	// The final-ACK regression depended on pump ordering. Keep independent
	// real application attempts after the denials; each still acquires fresh
	// authority and must deliver exact bytes, final status and closure receipts.
	positive := cases[len(cases)-1]
	for repeat := 0; repeat < 12; repeat++ {
		attempt := positive
		attempt.name = fmt.Sprintf("positive_control_repeat_%02d", repeat)
		cases = append(cases, attempt)
	}
	check := func(t *testing.T, test curlCase) {
		t.Helper()
		before, beforeHTTP, beforeAuth := v.connections.Load(), requests.Load(), authenticated.Load()
		var beforeSessions, afterSessions int64
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&beforeSessions))
		// The entire ancestor chain must be protected; even a private child
		// of sticky /tmp is deliberately rejected by the production IPC walk.
		endpointDirectory, err := os.MkdirTemp(dir, "curl-")
		must(t, err)
		t.Cleanup(func() { must(t, os.RemoveAll(endpointDirectory)) })
		endpoint := filepath.Join(endpointDirectory, "application.sock")
		// Establish this positive fixture precondition before interpreting any
		// later denial. Closing the probe removes only its own new endpoint.
		probe, err := localipc.Listen(endpoint)
		must(t, err)
		must(t, probe.Close())
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("observed destination/HTTP/authenticated deltas: %d/%d/%d", v.connections.Load()-before, requests.Load()-beforeHTTP, authenticated.Load()-beforeAuth)
			}
		})
		args := []string{"agent", "exec", "--socket", socket, "--resource", test.id, "--revision", strconv.FormatInt(test.revision, 10), "--endpoint", endpoint, "--", "/usr/bin/curl", "-q", "--silent", "--fail", "--max-time", "12", "--connect-timeout", "8", "--http1.1", "--noproxy", "*", "--proxy", "", "--cacert", test.trust, "--unix-socket", "{socket}", "--url", "https://" + test.host + "/media"}
		if test.auth {
			args = append(args, "--header", "@"+headers)
		}
		bindOnCatalog.Store(true)
		p := guestStartApplication(t, args...)
		must(t, p.input.Close())
		message := "Local application launch failed.\n"
		if test.success {
			message = ""
		}
		output := guestSecretApplicationResult(t, p, test.success, message)
		if (test.success && !bytes.Equal(output, payload)) || (!test.success && len(output) != 0) {
			t.Fatal("curl output did not match authenticated application response")
		}
		carrierEventually(t, func() bool { return v.closed.Load() == v.connections.Load() })
		if shutdownInvalid.Load() {
			t.Fatal("positive destination did not finish TLS and TCP without trailing data")
		}
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&afterSessions))
		if v.connections.Load()-before != test.connections || requests.Load()-beforeHTTP != test.http || metadataInvalid.Load() {
			t.Fatalf("destination/HTTP counts=%d/%d want=%d/%d; invalid Host/SNI=%t", v.connections.Load()-before, requests.Load()-beforeHTTP, test.connections, test.http, metadataInvalid.Load())
		}
		if test.connections == 0 && beforeSessions != afterSessions {
			t.Fatal("denied selection acquired remote authority")
		}
		expectedAuth := int64(0)
		if test.success {
			expectedAuth = 1
		}
		if authenticated.Load()-beforeAuth != expectedAuth {
			t.Fatal("application authentication was bypassed")
		}
		if _, err := os.Lstat(endpoint); !os.IsNotExist(err) {
			t.Fatal("launcher retained its endpoint")
		}
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) { check(t, test) })
	}
	t.Run("revoked_enrollment_has_no_new_destination", func(t *testing.T) {
		must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(invitation) }))
		check(t, curlCase{"revoked", "localhost", rootFile, v.resource.ID, v.resource.Revision, true, false, 0, 0})
	})
	session.finish(t)
	t.Run("routing_dns_and_forwarding_unchanged", func(t *testing.T) {
		for name, state := range applicationNetworkSnapshot(t) {
			if networkBefore[name] != state {
				t.Errorf("application workflow changed guest network setting: %s", name)
			}
		}
	})
	if !t.Failed() {
		t.Log("restricted issuer process, encrypted enrollment, actual agent/curl, exact binary HTTPS, Host/SNI, certificate and application-authentication denials, exact selection/revocation, destination closures/receipts and identity preservation")
	}
}
