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
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/connector"
	"portico.local/portico/internal/control"
	enroll "portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
)

func guestSecretApplication(t *testing.T, secret any, args ...string) *guestApplication {
	t.Helper()
	requireWorkloadGuest(t)
	data, err := json.Marshal(secret)
	must(t, err)
	defer clear(data)
	if len(data) > 4096 {
		t.Fatal("fixture secret exceeds pipe capacity")
	}
	reader, writer, err := os.Pipe()
	must(t, err)
	defer reader.Close()
	defer writer.Close()
	_, err = writer.Write(data)
	must(t, err)
	must(t, writer.Close())
	return guestStartApplicationWithFiles(t, []*os.File{reader}, args...)
}

func guestSecretResult(t *testing.T, secret any, success bool, message string, args ...string) []byte {
	t.Helper()
	p := guestSecretApplication(t, secret, args...)
	// Password processing uses the production KDF. This bounds process startup,
	// not network operations, policy leases or authority-closure deadlines.
	must(t, p.output.SetReadDeadline(time.Now().Add(90*time.Second)))
	output, err := io.ReadAll(io.LimitReader(p.output, 64<<10))
	must(t, err)
	p.ended(t, success, message)
	if bytes.Contains(output, []byte("encrypted-client-fixture-passphrase")) || bytes.Contains(p.logs.Bytes(), []byte("encrypted-client-fixture-passphrase")) {
		t.Fatal("command exposed unlock material")
	}
	return output
}

func TestWorkloadGuestEncryptedClientEnrollmentAndRevocation(t *testing.T) {
	v := newWorkloadFixture(t) // Guard before any real destination socket.
	f := v.carrier.policy.device.f
	h := enrollmentHTTP(t, v.carrier.policy.device, v.carrier.policy.device.provider(t))
	priorSignatures := h.f.calls.Load()
	connectorPath, _, _ := guestConnectorConfiguration(t, v, 1)
	runCtx, cancel := context.WithCancel(context.Background())
	startConnector := make(chan struct{})
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
			t.Error("encrypted-client connector did not join")
		}
	})
	var bindOnCatalog atomic.Bool
	path, file := guestClientConfiguration(t, v, connectorPath, func(server *PolicyHTTPServer) {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Establish the first fixture binding after the real CLI has unlocked
			// and completed TLS. Its ordinary catalog/authorization handler still
			// executes unchanged, and all production deadlines remain in force.
			if bindOnCatalog.CompareAndSwap(true, false) {
				close(startConnector)
				timer := time.NewTimer(3 * time.Second)
				defer timer.Stop()
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
				for v.carrier.relay.Stats().Waiting != 1 {
					select {
					case <-r.Context().Done():
						return
					case <-timer.C:
						http.Error(w, "fixture binding unavailable", http.StatusServiceUnavailable)
						return
					case <-tick.C:
					}
				}
			}
			handler.ServeHTTP(w, r)
		})
	})
	dir := filepath.Dir(path)
	writeJSON := func(path string, value any) {
		data, err := json.Marshal(value)
		must(t, err)
		must(t, os.WriteFile(path, data, 0600))
	}
	invitation := NewID()
	secret, err := f.s.Invite(ctx, f.actor, InvitationSpec{ID: invitation, IssuerID: h.config.Trust.IssuerID(), PrincipalID: f.device.ID, Profile: pki.Device, ExpiresAt: f.s.now().Add(10 * time.Minute), NotAfter: h.config.NotAfter})
	must(t, err)
	serverRoot := filepath.Join(dir, "enrollment-server.pem")
	must(t, os.WriteFile(serverRoot, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.config.Redemption.ServerRootDER}), 0600))
	enrollmentPath := filepath.Join(dir, "enrollment.json")
	enrollmentFile := enroll.FileConfig{
		Version: 1, DeploymentID: file.DeploymentID, Profile: pki.Device, Issuer: file.Devices,
		PrincipalID: f.device.ID, InvitationID: invitation, NotAfter: h.config.NotAfter.UTC().Format(time.RFC3339), StateFile: filepath.Join(dir, "device.age"),
		Redemption: identityfile.EndpointFiles{URL: h.config.Redemption.URL, RootCertificateFile: serverRoot, SPKI: h.config.Redemption.ServerSPKI},
		Activation: identityfile.EndpointFiles{URL: h.config.Activation.URL, RootCertificateFile: serverRoot, SPKI: h.config.Activation.ServerSPKI}, OperationTimeoutMillis: 5000,
	}
	writeJSON(enrollmentPath, enrollmentFile)
	// Remove the earlier fixture identity: only the newly enrolled encrypted
	// software key can supply this client's TLS proof.
	must(t, os.Remove(file.IdentityKeyFile))
	must(t, os.Remove(file.IdentityCertificateFile))
	file.Version, file.IdentityKeyFile, file.IdentityCertificateFile, file.EnrollmentConfigFile = 2, "", "", enrollmentPath
	writeJSON(path, file)
	const passphrase = "encrypted-client-fixture-passphrase"
	unlock := map[string]string{"passphrase": passphrase}
	operation := func(name string, input any, expected string) {
		t.Helper()
		output := guestSecretResult(t, input, true, "", "enroll", name, "--config", enrollmentPath, "--secrets-fd", "3")
		if string(output) != expected || bytes.Contains(output, []byte(secret)) {
			t.Fatal("enrollment command changed fixed output or exposed the invitation")
		}
	}
	operation("prepare", map[string]string{"passphrase": passphrase, "confirmation": passphrase}, "Encrypted enrollment attempt prepared.\n")
	original, err := os.ReadFile(enrollmentFile.StateFile)
	must(t, err)
	operation("redeem", map[string]string{"passphrase": passphrase, "invitation_secret": secret}, "Enrollment certificate retained. Activation is required.\n")
	originalCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
	must(t, err)
	guestSynchronizedClockFixture(t)
	catalogArgs := []string{"client", "catalog", "--config", path, "--secrets-fd", "3"}
	connectArgs := func(id string, revision int64) []string {
		return []string{"client", "connect", "--config", path, "--resource", id, "--revision", strconv.FormatInt(revision, 10), "--secrets-fd", "3"}
	}
	assertNoAuthority := func(t *testing.T) {
		t.Helper()
		var sessions int
		must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&sessions))
		if sessions != 0 || v.connections.Load() != 0 {
			t.Fatal("rejected encrypted client obtained authority or opened a destination")
		}
	}
	t.Run("retained_certificate_requires_activation", func(t *testing.T) {
		guestSecretResult(t, unlock, false, "Client resource connection failed.\n", catalogArgs...)
		assertNoAuthority(t)
	})
	operation("activate", unlock, "Enrollment activation confirmed.\n")
	t.Run("catalog_from_encrypted_identity", func(t *testing.T) {
		output := guestSecretResult(t, unlock, true, "", catalogArgs...)
		var catalog control.CatalogSnapshot
		must(t, json.Unmarshal(output, &catalog))
		found := false
		for _, r := range catalog.Resources {
			if r.ID == v.resource.ID {
				found = r.Revision == v.resource.Revision && r.ConnectorID == v.resource.ConnectorID && r.Address == v.resource.Address && r.Port == v.resource.Port && r.Protocol == "tcp"
			}
		}
		if catalog.Version != 1 || !found {
			t.Fatal("encrypted client lost the approved exact resource tuple")
		}
		assertNoAuthority(t)
	})
	t.Run("wrong_password", func(t *testing.T) {
		guestSecretResult(t, map[string]string{"passphrase": passphrase + "wrong"}, false, "Client configuration rejected.\n", catalogArgs...)
		assertNoAuthority(t)
	})
	for _, name := range []string{"plaintext_fallback", "changed_trust", "unexpected_secret_field"} {
		t.Run(name, func(t *testing.T) {
			changed := file
			input := map[string]string{"passphrase": passphrase}
			switch name {
			case "plaintext_fallback":
				changed.IdentityKeyFile = filepath.Join(dir, "client-key.pem")
			case "changed_trust":
				changed.Devices.IssuerID = NewID()
			case "unexpected_secret_field":
				input["invitation_secret"] = secret
			}
			writeJSON(path, changed)
			defer writeJSON(path, file)
			guestSecretResult(t, input, false, "Client configuration rejected.\n", catalogArgs...)
			assertNoAuthority(t)
		})
	}
	for _, selection := range []struct {
		name, id string
		revision int64
	}{{"unknown_resource", NewID(), 1}, {"wrong_revision", v.resource.ID, v.resource.Revision + 1}} {
		t.Run(selection.name, func(t *testing.T) {
			guestSecretResult(t, unlock, false, "Client resource connection failed.\n", connectArgs(selection.id, selection.revision)...)
			assertNoAuthority(t)
		})
	}
	t.Run("transfer_then_revoke_enrollment", func(t *testing.T) {
		bindOnCatalog.Store(true)
		p := guestSecretApplication(t, unlock, connectArgs(v.resource.ID, v.resource.Revision)...)
		payload := []byte{'e', 'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', 0, 0xff, '\n'}
		must(t, p.input.SetWriteDeadline(time.Now().Add(90*time.Second)))
		_, err := p.input.Write(payload)
		must(t, err)
		must(t, p.output.SetReadDeadline(time.Now().Add(90*time.Second)))
		got := make([]byte, len(payload))
		_, err = io.ReadFull(p.output, got)
		must(t, err)
		if !bytes.Equal(got, payload) || v.connections.Load() != 1 || v.received.Load() != int64(len(payload)) {
			t.Fatal("encrypted identity did not carry exact application bytes")
		}
		must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(invitation) }))
		p.ended(t, false, "Client resource connection failed.\n")
		carrierEventually(t, func() bool {
			var receipts int
			return f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts) == nil && receipts == 1 && v.closed.Load() == 1
		})
		guestSecretResult(t, unlock, false, "Client resource connection failed.\n", connectArgs(v.resource.ID, v.resource.Revision)...)
		if v.connections.Load() != 1 {
			t.Fatal("new encrypted client process reused revoked authority")
		}
	})
	retained, err := os.ReadFile(enrollmentFile.StateFile)
	must(t, err)
	retainedCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
	must(t, err)
	if !bytes.Equal(original, retained) || !bytes.Equal(originalCertificate, retainedCertificate) || h.f.calls.Load() != priorSignatures+1 {
		t.Fatal("resource access altered enrollment state or requested another signature")
	}
	t.Log("real encrypted client processes: activation gating, exact catalog, seven denials, exact application transfer, enrollment revocation and closure receipt; original ciphertext retained")
}
