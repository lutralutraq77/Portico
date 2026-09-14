//go:build linux

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/connector"
	"portico.local/portico/internal/control"
	enroll "portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
)

// This additional guard keeps real systemd control out of the ordinary guest,
// developer host and container suites. The dedicated guest has no NIC/shares.
func TestSystemdGuestAgentEnrollmentAndRevocation(t *testing.T) {
	if os.Getenv("PORTICO_SYSTEMD_FIXTURE") != "1" {
		t.Skip("requires dedicated NIC-less systemd guest")
	}
	requireWorkloadGuest(t)
	pid1, err := os.ReadFile("/proc/1/comm")
	must(t, err)
	marker, err := os.ReadFile("/portico-systemd-isolated-fixture")
	must(t, err)
	if os.Geteuid() != 0 || string(pid1) != "systemd\n" || string(marker) != "192.0.2.10\n" {
		t.Fatal("not the dedicated service fixture")
	}
	credential := func() *syscall.SysProcAttr {
		return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}}
	}
	unit := func(t *testing.T, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", append([]string{"--user"}, args...)...)
		cmd.SysProcAttr = credential()
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/home/porticofixture", "LANG=C", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture user-manager operation failed: %v %q", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	const service = "portico-agent.service"
	const socket = "/run/user/1000/portico-agent/agent.sock"
	const directory = "/home/porticofixture/.config/portico"
	const passphrase = "encrypted-client-fixture-passphrase"
	plain := func(t *testing.T, args ...string) *guestApplication {
		t.Helper()
		return guestStartConfiguredApplication(t, nil, credential(), args...)
	}
	secretCommand := func(t *testing.T, secret any, args ...string) *guestApplication {
		t.Helper()
		return guestSecretConfiguredApplication(t, secret, credential(), args...)
	}
	secretResult := func(t *testing.T, secret any, expected string, args ...string) {
		t.Helper()
		out := guestSecretApplicationResult(t, secretCommand(t, secret, args...), true, "")
		if string(out) != expected {
			t.Fatal("secret operation changed fixed output")
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		must(t, os.WriteFile(path, data, 0600))
		must(t, os.Chown(path, 1000, 1000))
	}
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		must(t, err)
		write(path, data)
	}
	v := newWorkloadFixtureWithCarrier(t, echoWorkloadDestination, func(c *carrier.Config) { c.PairTimeout = 10 * time.Second })
	f := v.carrier.policy.device.f
	h := enrollmentHTTP(t, v.carrier.policy.device, v.carrier.policy.device.provider(t))
	priorSignatures := h.f.calls.Load()
	connectorPath, _, _ := guestConnectorConfiguration(t, v, 1)
	runCtx, cancel := context.WithCancel(context.Background())
	startConnector := make(chan struct{})
	var startOnce sync.Once
	connectorDone := make(chan error, 1)
	go func() {
		select {
		case <-startConnector:
			connectorDone <- connector.Run(runCtx, v.carrier.connector, v.server, connector.Options{Workers: 1, RetryMin: 250 * time.Millisecond, RetryMax: time.Second})
		case <-runCtx.Done():
			connectorDone <- nil
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-connectorDone:
			must(t, err)
		case <-time.After(5 * time.Second):
			t.Error("service fixture connector did not join")
		}
	})
	var bindOnCatalog atomic.Bool
	_, file := guestClientConfiguration(t, v, connectorPath, func(server *PolicyHTTPServer) {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bindOnCatalog.CompareAndSwap(true, false) {
				startOnce.Do(func() { close(startConnector) })
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
				for v.carrier.relay.Stats().Waiting != 1 {
					select {
					case <-r.Context().Done():
						return
					case <-deadline.C:
						http.Error(w, "fixture binding unavailable", http.StatusServiceUnavailable)
						return
					case <-tick.C:
					}
				}
			}
			handler.ServeHTTP(w, r)
		})
	})
	// Copy only public trust into the user's protected directory. The fixture
	// controller/connector private keys stay in their root-owned private paths.
	for _, path := range []*string{&file.Devices.RootCertificateFile, &file.Devices.IssuerCertificateFile, &file.Connectors.RootCertificateFile, &file.Connectors.IssuerCertificateFile, &file.Control.RootCertificateFile, &file.Carrier.RootCertificateFile} {
		data, err := os.ReadFile(*path)
		must(t, err)
		*path = filepath.Join(directory, filepath.Base(*path))
		write(*path, data)
	}
	must(t, os.Remove(file.IdentityKeyFile))
	must(t, os.Remove(file.IdentityCertificateFile))
	invitation := NewID()
	invitationSecret, err := f.s.Invite(ctx, f.actor, InvitationSpec{ID: invitation, IssuerID: h.config.Trust.IssuerID(), PrincipalID: f.device.ID, Profile: pki.Device, ExpiresAt: f.s.now().Add(10 * time.Minute), NotAfter: h.config.NotAfter})
	must(t, err)
	serverRoot := filepath.Join(directory, "enrollment-server.pem")
	write(serverRoot, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.config.Redemption.ServerRootDER}))
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	enrollmentFile := enroll.FileConfig{
		Version: 1, DeploymentID: file.DeploymentID, Profile: pki.Device, Issuer: file.Devices,
		PrincipalID: f.device.ID, InvitationID: invitation, NotAfter: h.config.NotAfter.UTC().Format(time.RFC3339), StateFile: filepath.Join(directory, "device.age"),
		Redemption: identityfile.EndpointFiles{URL: h.config.Redemption.URL, RootCertificateFile: serverRoot, SPKI: h.config.Redemption.ServerSPKI},
		Activation: identityfile.EndpointFiles{URL: h.config.Activation.URL, RootCertificateFile: serverRoot, SPKI: h.config.Activation.ServerSPKI}, OperationTimeoutMillis: 5000,
	}
	writeJSON(enrollmentPath, enrollmentFile)
	file.Version, file.IdentityKeyFile, file.IdentityCertificateFile, file.EnrollmentConfigFile = 2, "", "", enrollmentPath
	writeJSON(filepath.Join(directory, "client.json"), file)
	unlock := map[string]string{"passphrase": passphrase}
	secretResult(t, map[string]string{"passphrase": passphrase, "confirmation": passphrase}, "Encrypted enrollment attempt prepared.\n", "enroll", "prepare", "--config", enrollmentPath, "--secrets-fd", "3")
	original, err := os.ReadFile(enrollmentFile.StateFile)
	must(t, err)
	secretResult(t, map[string]string{"passphrase": passphrase, "invitation_secret": invitationSecret}, "Enrollment certificate retained. Activation is required.\n", "enroll", "redeem", "--config", enrollmentPath, "--secrets-fd", "3")
	originalCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
	must(t, err)
	guestSynchronizedClockFixture(t)
	secretResult(t, unlock, "Enrollment activation confirmed.\n", "enroll", "activate", "--config", enrollmentPath, "--secrets-fd", "3")
	unit(t, "start", service)
	t.Cleanup(func() { unit(t, "stop", service) })
	status := func(t *testing.T, expected string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			if _, err := os.Lstat(socket); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("service socket did not appear")
			}
			time.Sleep(20 * time.Millisecond)
		}
		out := guestSecretApplicationResult(t, plain(t, "agent", "status", "--socket", socket), true, "")
		if string(out) != "{\"version\":1,\"state\":\""+expected+"\"}\n" {
			t.Fatal("unexpected user-service lock state")
		}
	}
	connect := func(t *testing.T) *guestApplication {
		return plain(t, "agent", "connect", "--socket", socket, "--resource", v.resource.ID, "--revision", strconv.FormatInt(v.resource.Revision, 10))
	}
	deny := func(t *testing.T) {
		t.Helper()
		before := v.connections.Load()
		var beforeSessions, afterSessions int64
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&beforeSessions))
		out := guestSecretApplicationResult(t, connect(t), false, "Local agent resource connection failed.\n")
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&afterSessions))
		if len(out) != 0 || before != v.connections.Load() || beforeSessions != afterSessions {
			t.Fatal("locked/revoked service acquired destination authority")
		}
	}
	unlockService := func(t *testing.T) {
		secretResult(t, unlock, "Local agent unlocked.\n", "agent", "unlock", "--socket", socket, "--secrets-fd", "3")
		status(t, "unlocked")
	}
	t.Run("installed_service_starts_locked_then_explicit_user_unlock", func(t *testing.T) {
		status(t, "locked")
		deny(t)
		unlockService(t)
		out := guestSecretApplicationResult(t, plain(t, "agent", "catalog", "--socket", socket), true, "")
		var catalog control.CatalogSnapshot
		must(t, json.Unmarshal(out, &catalog))
		found := false
		for _, row := range catalog.Resources {
			if row.ID == v.resource.ID && row.Revision == v.resource.Revision && row.ConnectorID == v.resource.ConnectorID && row.Protocol == "tcp" && row.Address == v.resource.Address && row.Port == v.resource.Port {
				found = true
			}
		}
		if catalog.Version != 1 || !found || v.connections.Load() != 0 {
			t.Fatal("service did not preserve exact inventory with zero destination authority")
		}
	})
	transfer := func(t *testing.T) *guestApplication {
		t.Helper()
		beforeConnections, beforeBytes := v.connections.Load(), v.received.Load()
		bindOnCatalog.Store(true)
		p := connect(t)
		payload := []byte{'u', 's', 'e', 'r', 0, 0xff, '\n'}
		must(t, p.input.SetWriteDeadline(time.Now().Add(15*time.Second)))
		_, err := p.input.Write(payload)
		must(t, err)
		must(t, p.output.SetReadDeadline(time.Now().Add(15*time.Second)))
		got := make([]byte, len(payload))
		_, err = io.ReadFull(p.output, got)
		must(t, err)
		if !bytes.Equal(got, payload) || v.connections.Load() != beforeConnections+1 || v.received.Load() != beforeBytes+int64(len(payload)) {
			t.Fatal("service transfer changed bytes/destination")
		}
		return p
	}
	closed := func(t *testing.T, p *guestApplication) {
		t.Helper()
		p.ended(t, false, "Local agent resource connection failed.\n")
		carrierEventually(t, func() bool {
			var receipts int64
			return f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts) == nil && receipts == v.connections.Load() && v.closed.Load() == receipts
		})
	}
	t.Run("manual_lock_closes_resource_and_requires_explicit_unlock", func(t *testing.T) {
		p := transfer(t)
		out := guestSecretApplicationResult(t, plain(t, "agent", "lock", "--socket", socket), true, "")
		if string(out) != "Local agent locked.\n" {
			t.Fatal("unexpected lock output")
		}
		closed(t, p)
		status(t, "locked")
		deny(t)
		unlockService(t)
	})
	t.Run("crash_during_transfer_restarts_locked_without_reusing_authority", func(t *testing.T) {
		p := transfer(t)
		oldPID := unit(t, "show", "--property=MainPID", "--value", service)
		unit(t, "kill", "--signal=SIGKILL", "--kill-whom=main", service)
		closed(t, p)
		deadline := time.Now().Add(20 * time.Second)
		for {
			pid := unit(t, "show", "--property=MainPID", "--value", service)
			if pid != "0" && pid != oldPID {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("service did not restart with a fresh process")
			}
			time.Sleep(50 * time.Millisecond)
		}
		status(t, "locked")
		deny(t)
		unlockService(t)
	})
	t.Run("revoked_enrollment_closes_resource_and_denies_fresh_calls", func(t *testing.T) {
		p := transfer(t)
		must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(invitation) }))
		closed(t, p)
		deny(t)
		out := guestSecretApplicationResult(t, plain(t, "agent", "catalog", "--socket", socket), false, "Local agent catalog failed.\n")
		if len(out) != 0 {
			t.Fatal("revoked service exposed inventory")
		}
	})
	unit(t, "stop", service)
	if _, err := os.Lstat(filepath.Dir(socket)); !os.IsNotExist(err) {
		t.Fatal("service retained runtime directory")
	}
	retained, err := os.ReadFile(enrollmentFile.StateFile)
	must(t, err)
	retainedCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
	must(t, err)
	if !bytes.Equal(original, retained) || !bytes.Equal(originalCertificate, retainedCertificate) || h.f.calls.Load() != priorSignatures+1 {
		t.Fatal("service lifecycle altered identity or signed again")
	}
	for _, path := range []string{enrollmentFile.StateFile, enrollmentFile.StateFile + ".certificate"} {
		var st syscall.Stat_t
		must(t, syscall.Stat(path, &st))
		if st.Uid != 1000 || st.Gid != 1000 || st.Mode&0777 != 0600 {
			t.Fatal("user-owned encrypted state permissions changed")
		}
	}
	journalContext, stopJournal := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopJournal()
	journal, err := exec.CommandContext(journalContext, "/usr/bin/journalctl", "--no-pager", "-b", "-n", "200", "_SYSTEMD_USER_UNIT="+service).Output()
	must(t, err)
	if bytes.Contains(journal, []byte(passphrase)) || bytes.Contains(journal, []byte(invitationSecret)) {
		t.Fatal("service journal exposed fixture secret material")
	}
	if !t.Failed() {
		t.Log("installed unit: uid1000 enrollment/explicit unlock, bytes, manual lock, crash restart locked, enrollment revocation, three destination closures/receipts, original encrypted state retained")
	}
}
