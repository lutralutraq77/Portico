//go:build linux

package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/pki"
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
	}
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
	// This one daemon spans an expensive production-KDF unlock plus all curl
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
