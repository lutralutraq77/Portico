//go:build dashboardbrowser

package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// This opt-in browser qualification uses a real private TLS server and live
// SQLite state. The exact-host CONNECT fixture avoids host DNS/certificate-store
// changes. Browser credentials are ephemeral software fixtures, not hardware.
func TestDashboardBrowser(t *testing.T) {
	testDashboardBrowser(t, false)
}

func TestDashboardPolicyBrowser(t *testing.T) {
	testDashboardBrowser(t, true)
}

func testDashboardBrowser(t *testing.T, management bool) {
	t.Helper()
	node, browser, report := os.Getenv("PORTICO_BROWSER_NODE"), os.Getenv("PORTICO_BROWSER_EXECUTABLE"), os.Getenv("PORTICO_BROWSER_REPORT")
	if !filepath.IsAbs(node) || !filepath.IsAbs(browser) || !filepath.IsAbs(report) {
		t.Fatal("browser qualification requires absolute node, browser and report paths")
	}
	a := adminSeed(t)
	if management {
		a.setupFactors(t)
	}
	for i := range 54 {
		name := fmt.Sprintf("Fixture person %02d", i)
		if i == 0 {
			name = `<img src=x onerror="globalThis.metadataExecuted=true">`
		}
		must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), name, true}) }))
		if management {
			must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error {
				return tx.AddConnector(Connector{ID: NewID(), Name: fmt.Sprintf("Fixture connector %02d", i), Version: "fixture", Enabled: true})
			}))
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	host := net.JoinHostPort("admin.portico.test", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	origin := "https://" + host
	key := a.keys[0]
	verifier, err := adminauth.New(adminauth.Config{Origin: origin, ValidUntil: time.Now().Add(time.Hour), Models: []adminauth.Model{{AAGUID: key.AAGUID.String(), RootsDER: [][]byte{key.Root.Raw}}}})
	must(t, err)
	root, rootKey := testfixture.Root(t)
	serverKey := newKey(t)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"admin.portico.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, &serverKey.PublicKey, rootKey)
	policy := policyFixtureFor(t, a.f)
	server, err := policy.engine.NewHTTPServer(PolicyHTTPConfig{Profile: pki.Administrator, Host: host, ServerIdentity: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: serverKey}, AdministratorTrust: a.trust, AdministratorVerifier: verifier})
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, server.Close(stop))
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("browser server shutdown: %v", err)
		}
	})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != host {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()
		client, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		_ = client.SetDeadline(time.Now().Add(90 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(90 * time.Second))
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(copied) }()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		<-copied
	}))
	t.Cleanup(proxy.Close)
	rootPath := filepath.Join(t.TempDir(), "browser-fixture-root.pem")
	must(t, os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0600))
	privateDER, err := x509.MarshalPKCS8PrivateKey(a.identity.PrivateKey)
	must(t, err)
	config := struct {
		Origin, Proxy, Certificate, Key, Browser, Report, DeviceCertificateID, ConnectorCertificateID, ResourceID string
		ConnectorID, DeviceID, UserID, CredentialID, CredentialKey, UserHandle                                    string
		SignCount                                                                                                 uint32
	}{
		Origin: origin, Proxy: proxy.URL, Browser: browser, Report: report,
		ResourceID:  a.f.f.resource.ID,
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.identity.Certificate[0]})),
		Key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
	}
	script := "test-dashboard-browser.cjs"
	if management {
		script = "test-dashboard-policy-browser.cjs"
		config.ConnectorID, config.DeviceID, config.UserID = a.f.f.connector.ID, a.f.f.device.ID, a.f.f.user.ID
		credentialDER, err := x509.MarshalPKCS8PrivateKey(key.Private)
		must(t, err)
		config.CredentialID = base64.StdEncoding.EncodeToString(key.ID)
		config.CredentialKey = base64.StdEncoding.EncodeToString(credentialDER)
		config.UserHandle = base64.StdEncoding.EncodeToString([]byte(a.f.f.user.ID))
		config.SignCount = key.Counter
	}
	must(t, a.f.f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(policy.deviceLeaf)).Scan(&config.DeviceCertificateID))
	must(t, a.f.f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(policy.connectorLeaf)).Scan(&config.ConnectorCertificateID))
	testContext, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(testContext, node, filepath.Join("..", "..", "scripts", script))
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+rootPath)
	in, err := command.StdinPipe()
	must(t, err)
	out, err := command.StdoutPipe()
	must(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	must(t, command.Start())
	must(t, json.NewEncoder(in).Encode(config))
	scanner := bufio.NewScanner(out)
	revoked, passed := false, false
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "PORTICO_BROWSER_POLICY_STATE":
			if !management {
				t.Fatal("policy state requested outside management fixture")
			}
			var snapshot struct{ Resources, Grants, Hosting, Applied int }
			for query, target := range map[string]*int{
				"SELECT count(*) FROM resource_heads":                           &snapshot.Resources,
				"SELECT count(*) FROM grants":                                   &snapshot.Grants,
				"SELECT count(*) FROM host_bindings":                            &snapshot.Hosting,
				"SELECT count(*) FROM audit_events WHERE action='policy.apply'": &snapshot.Applied,
			} {
				must(t, a.f.f.s.db.QueryRow(query).Scan(target))
			}
			must(t, json.NewEncoder(in).Encode(snapshot))
		case "PORTICO_BROWSER_POLICY_CHANGE":
			if !management {
				t.Fatal("policy mutation requested outside management fixture")
			}
			must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Concurrent policy change", true}) }))
			_, err = fmt.Fprintln(in, "policy_changed")
			must(t, err)
		case "PORTICO_BROWSER_DISABLE_GRANT":
			must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("grant", a.f.f.grant.ID) }))
			if _, err := policy.engine.Authorize(ctx, policy.connectorConn, policy.request()); err == nil {
				t.Fatal("browser fixture grant removal did not deny real authorization")
			}
			_, err = fmt.Fprintln(in, "grant_disabled")
			must(t, err)
		case "PORTICO_BROWSER_REVOKE":
			must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
			revoked = true
			_, err = fmt.Fprintln(in, "revoked")
			must(t, err)
		case "PORTICO_DASHBOARD_BROWSER_PASS":
			passed = true
		default:
			if strings.HasPrefix(line, "BROWSER_CHECK ") {
				t.Log(line)
			}
		}
	}
	must(t, scanner.Err())
	_ = in.Close()
	if err := command.Wait(); err != nil || !revoked || !passed {
		t.Fatalf("browser qualification failed: %v; revoked=%t passed=%t; %s", err, revoked, passed, stderr.String())
	}
}
