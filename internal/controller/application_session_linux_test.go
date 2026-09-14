//go:build linux

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"portico.local/portico/internal/agent"
	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/connector"
	enroll "portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
)

// HTTPS and SSH share the real restricted issuer, encrypted enrollment and
// daemon setup. Each invocation owns independent identities and destinations.
type applicationSession struct {
	v                       *workloadFixture
	dir, socket, invitation string
	write                   func(string, []byte) string
	bindOnCatalog           *atomic.Bool
	bindFresh               func(*testing.T)
	unlock                  func(*testing.T)
	finish                  func(*testing.T)
}

func newApplicationSession(t *testing.T, destination func(net.Conn)) *applicationSession {
	t.Helper()
	requireArchApplicationGuest(t)
	v := newWorkloadFixtureWithCarrier(t, destination, func(c *carrier.Config) { c.PairTimeout = 10 * time.Second })
	f := v.carrier.policy.device.f
	issuer := applicationIssuer(t, v.carrier.policy.device)
	var issues atomic.Int64
	h := enrollmentHTTP(t, v.carrier.policy.device, issueFunc(func(c context.Context, r IssuanceRequest) ([]byte, error) {
		issues.Add(1)
		started := time.Now()
		certificate, err := issuer.Issue(c, r)
		t.Logf("restricted issuer request completed in %s; success=%t context_expired=%t", time.Since(started), err == nil, c.Err() != nil)
		return certificate, err
	}))
	connectorPath, _, _ := guestConnectorConfiguration(t, v, 1)
	runContext, cancel := context.WithCancel(ctx)
	start := make(chan struct{})
	var once sync.Once
	connectorDone := make(chan error, 1)
	go func() {
		select {
		case <-start:
			connectorDone <- connector.Run(runContext, v.carrier.connector, v.server, connector.Options{Workers: 1, RetryMin: 250 * time.Millisecond, RetryMax: time.Second})
		case <-runContext.Done():
			connectorDone <- nil
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-connectorDone:
			must(t, err)
		case <-time.After(5 * time.Second):
			t.Error("application connector failed to join")
		}
	})
	var bindOnCatalog atomic.Bool
	path, file := guestClientConfiguration(t, v, connectorPath, func(server *PolicyHTTPServer) {
		handler := server.server.Handler
		server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bindOnCatalog.CompareAndSwap(true, false) {
				once.Do(func() { close(start) })
				deadline := time.Now().Add(3 * time.Second)
				for v.carrier.relay.Stats().Waiting != 1 {
					if time.Now().After(deadline) || r.Context().Err() != nil {
						http.Error(w, "fixture binding unavailable", http.StatusServiceUnavailable)
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			handler.ServeHTTP(w, r)
		})
	})
	dir := filepath.Dir(path)
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, data, 0600))
		return path
	}
	writeJSON := func(name string, data any) string {
		encoded, err := json.Marshal(data)
		must(t, err)
		return write(name, encoded)
	}
	invitation := NewID()
	t.Cleanup(func() {
		if t.Failed() {
			var state string
			if f.s.db.QueryRow("SELECT state FROM enrollments WHERE id=?", invitation).Scan(&state) != nil {
				state = "unavailable"
			}
			t.Logf("enrollment fixture final state=%s; restricted issuer calls=%d", state, issues.Load())
		}
	})
	secret, err := f.s.Invite(ctx, f.actor, InvitationSpec{ID: invitation, IssuerID: h.config.Trust.IssuerID(), PrincipalID: f.device.ID, Profile: pki.Device, ExpiresAt: f.s.now().Add(10 * time.Minute), NotAfter: h.config.NotAfter})
	must(t, err)
	serverRoot := write("enrollment-server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.config.Redemption.ServerRootDER}))
	enrollmentFile := enroll.FileConfig{Version: 1, DeploymentID: file.DeploymentID, Profile: pki.Device, Issuer: file.Devices, PrincipalID: f.device.ID, InvitationID: invitation, NotAfter: h.config.NotAfter.UTC().Format(time.RFC3339), StateFile: filepath.Join(dir, "application-device.age"), Redemption: identityfile.EndpointFiles{URL: h.config.Redemption.URL, RootCertificateFile: serverRoot, SPKI: h.config.Redemption.ServerSPKI}, Activation: identityfile.EndpointFiles{URL: h.config.Activation.URL, RootCertificateFile: serverRoot, SPKI: h.config.Activation.ServerSPKI}, OperationTimeoutMillis: 5000}
	enrollmentPath := writeJSON("application-enrollment.json", enrollmentFile)
	must(t, os.Remove(file.IdentityKeyFile))
	must(t, os.Remove(file.IdentityCertificateFile))
	file.Version, file.IdentityKeyFile, file.IdentityCertificateFile, file.EnrollmentConfigFile = 2, "", "", enrollmentPath
	writeJSON(filepath.Base(path), file)
	const passphrase = "encrypted-client-fixture-passphrase"
	unlock := map[string]string{"passphrase": passphrase}
	operation := func(name string, input any, expected string) {
		started := time.Now()
		p := guestSecretApplication(t, input, "enroll", name, "--config", enrollmentPath, "--secrets-fd", "3")
		if output := guestSecretApplicationResult(t, p, true, ""); string(output) != expected {
			t.Fatal("unexpected enrollment output")
		}
		t.Logf("encrypted enrollment %s completed in %s", name, time.Since(started))
	}
	operation("prepare", map[string]string{"passphrase": passphrase, "confirmation": passphrase}, "Encrypted enrollment attempt prepared.\n")
	operation("redeem", map[string]string{"passphrase": passphrase, "invitation_secret": secret}, "Enrollment certificate retained. Activation is required.\n")
	guestSynchronizedClockFixture(t)
	operation("activate", unlock, "Enrollment activation confirmed.\n")
	original, err := os.ReadFile(enrollmentFile.StateFile)
	must(t, err)
	originalCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
	must(t, err)
	socket := filepath.Join(dir, "application-agent.sock")
	// This one daemon spans an expensive production-KDF unlock plus all application
	// cases. Its fixture lifetime does not extend any resource or RPC deadline.
	daemon := guestStartApplicationLifetime(t, 4*time.Minute, nil, nil, "agent", "daemon", "--config", path, "--socket", socket)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("application agent failed to start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	unlockStarted := time.Now()
	unlockProcess := guestSecretApplication(t, unlock, "agent", "unlock", "--socket", socket, "--secrets-fd", "3")
	if output := guestSecretApplicationResult(t, unlockProcess, true, ""); string(output) != "Local agent unlocked.\n" {
		t.Fatal("application agent unlock failed")
	}
	t.Logf("encrypted application agent unlock completed in %s", time.Since(unlockStarted))
	catalog, err := agent.Catalog(ctx, socket)
	must(t, err)
	// The shared workload fixture retains its original resource as well as
	// this HTTPS destination. Validate the selected tuple, not catalog size.
	selected := 0
	for _, resource := range catalog {
		if resource.ID == v.resource.ID {
			selected++
			if resource.Revision != v.resource.Revision || resource.ConnectorID != v.resource.ConnectorID || resource.Address != v.resource.Address || resource.Port != v.resource.Port || resource.Protocol != v.resource.Protocol {
				t.Fatal("unlocked application agent changed the selected resource tuple")
			}
		}
	}
	if selected != 1 {
		t.Fatalf("unlocked application agent has %d selected entries in %d catalog resources", selected, len(catalog))
	}
	t.Logf("unlocked application agent catalog contains its exact resource among %d entries", len(catalog))
	return &applicationSession{v: v, dir: dir, socket: socket, invitation: invitation, write: write, bindOnCatalog: &bindOnCatalog,
		bindFresh: func(t *testing.T) {
			t.Helper()
			before := v.carrier.admitted.Load()
			once.Do(func() { close(start) })
			deadline := time.Now().Add(8 * time.Second)
			for v.carrier.admitted.Load() <= before || v.carrier.relay.Stats().Waiting != 1 {
				select {
				case err := <-connectorDone:
					connectorDone <- err // the parent cleanup must still join
					t.Fatalf("application fixture connector ended: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("fresh application fixture binding unavailable")
				}
				time.Sleep(5 * time.Millisecond)
			}
		},
		unlock: func(t *testing.T) {
			t.Helper()
			process := guestSecretApplication(t, unlock, "agent", "unlock", "--socket", socket, "--secrets-fd", "3")
			if output := guestSecretApplicationResult(t, process, true, ""); string(output) != "Local agent unlocked.\n" {
				t.Fatal("application agent re-unlock failed")
			}
		},
		finish: func(t *testing.T) {
			t.Helper()
			carrierEventually(t, func() bool {
				var receipts int64
				return f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts) == nil && receipts == v.connections.Load()
			})
			must(t, daemon.command.Process.Signal(syscall.SIGTERM))
			if output := guestSecretApplicationResult(t, daemon, true, ""); string(output) != "Local agent daemon stopped.\n" {
				t.Fatal("application daemon shutdown failed")
			}
			retained, err := os.ReadFile(enrollmentFile.StateFile)
			must(t, err)
			retainedCertificate, err := os.ReadFile(enrollmentFile.StateFile + ".certificate")
			must(t, err)
			if !bytes.Equal(original, retained) || !bytes.Equal(originalCertificate, retainedCertificate) || issues.Load() != 1 {
				t.Fatal("application access changed encrypted identity or repeated issuance")
			}

		},
	}
}
