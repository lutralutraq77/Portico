//go:build linux && dashboardbrowser

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/adminapp"
	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/adminkey"
	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// This opt-in test executes the installed, unmodified command and shipped
// main.cjs. It uses no debug port, preload, alternate entry point or clock hook.
func TestInstalledAdministratorCommand(t *testing.T) {
	if os.Getenv("PORTICO_INSTALLED_ADMIN_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Geteuid() == 0 {
		t.Fatal("installed administrator qualification requires the isolated non-root CI runner")
	}
	uncertainty, err := clockhealth.Uncertainty()
	must(t, err)
	t.Logf("actual read-only kernel clock uncertainty: %s", uncertainty)
	base, err := os.MkdirTemp(".", ".portico-installed-admin-")
	must(t, err)
	base, err = filepath.Abs(base)
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	state := filepath.Join(base, "state")
	must(t, os.Mkdir(state, 0700))
	f := enrollmentSeed(t)
	root, rootKey := testfixture.Root(t)
	issuerKey := newKey(t)
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated installed administrator issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}, root, issuerKey.Public(), rootKey)
	trust, err := pki.NewTrust(pki.Config{DeploymentID: f.config.DeploymentID, IssuerID: NewID(), Profile: pki.Administrator, RootDER: root.Raw, IssuerDER: issuer.Raw})
	must(t, err)
	keyPath := filepath.Join(base, "administrator.age")
	passphrase := []byte("isolated installed administrator passphrase")
	defer clear(passphrase)
	key, err := adminkey.Create(keyPath, trust, f.f.device.ID, passphrase)
	must(t, err)
	defer key.Close()
	csrDER, err := key.CSR()
	must(t, err)
	csr, err := pki.ParseCSR(csrDER)
	must(t, err)
	uri, err := pki.IdentityURI(f.config.DeploymentID, pki.Administrator, f.f.device.ID)
	must(t, err)
	certificate := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, issuer, csr.PublicKey, issuerKey)
	key.Close()
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RegisterAdminDevice(f.f.user.ID, f.f.device.ID, trust, certificate.Raw) }))
	writeCertificate := func(name string, der []byte) string {
		path := filepath.Join(base, name)
		must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		return path
	}
	serverRoot, serverRootKey := testfixture.Root(t)
	serverKey := newKey(t)
	serverLeaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"admin.portico.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, serverRoot, serverKey.Public(), serverRootKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	host := "admin.portico.test"
	verifier, err := adminauth.New(adminauth.Config{Origin: "https://" + host, ValidUntil: time.Now().Add(time.Hour), Models: []adminauth.Model{chromiumBrowserModel(t)}})
	must(t, err)
	policy := policyFixtureFor(t, f)
	server, err := policy.engine.NewHTTPServer(PolicyHTTPConfig{Profile: pki.Administrator, Host: host, ServerIdentity: tls.Certificate{Certificate: [][]byte{serverLeaf.Raw}, PrivateKey: serverKey}, AdministratorTrust: trust, AdministratorVerifier: verifier})
	must(t, err)
	var mu sync.Mutex
	seen := map[string]int{}
	ready := make(chan struct{})
	var once sync.Once
	handler := server.server.Handler
	server.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &installedResponse{ResponseWriter: w, status: 200}
		handler.ServeHTTP(response, r)
		if response.status == 200 {
			mu.Lock()
			seen[r.URL.Path]++
			loaded := seen["/admin"] > 0 && seen["/admin.js"] > 0 && seen["/admin.css"] > 0 && seen["/api/v1/admin/dashboard/inventory"] > 0
			mu.Unlock()
			if loaded {
				once.Do(func() { close(ready) })
			}
		}
	})
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		must(t, server.Close(closeContext))
		if err := <-served; err != http.ErrServerClosed {
			t.Errorf("installed fixture server: %v", err)
		}
	})
	configuration := adminapp.FileConfig{Version: 1, DeploymentID: f.config.DeploymentID, PrincipalID: f.f.device.ID, Administrators: identityfile.TrustFiles{IssuerID: trust.IssuerID(), RootCertificateFile: writeCertificate("admin-root.pem", root.Raw), IssuerCertificateFile: writeCertificate("admin-issuer.pem", issuer.Raw)}, IdentityCertificateFile: writeCertificate("admin-leaf.pem", certificate.Raw), EncryptedKeyFile: keyPath, Server: identityfile.EndpointFiles{URL: "https://" + host, RootCertificateFile: writeCertificate("server-root.pem", serverRoot.Raw), SPKI: pki.Hash(serverLeaf.RawSubjectPublicKeyInfo)}, BootstrapAddress: listener.Addr().String(), StateDirectory: state, OperationTimeoutMillis: 5000, SessionLifetimeSeconds: 120}
	data, err := json.Marshal(configuration)
	must(t, err)
	configPath := filepath.Join(base, "admin.json")
	must(t, os.WriteFile(configPath, data, 0600))
	original, err := os.ReadFile(keyPath)
	must(t, err)
	secret, err := json.Marshal(map[string]string{"passphrase": string(passphrase)})
	must(t, err)
	defer clear(secret)
	bounded, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	input, output, err := os.Pipe()
	must(t, err)
	defer input.Close()
	defer output.Close()
	command := exec.CommandContext(bounded, "/usr/bin/portico", "admin", "open", "--config", configPath, "--secrets-fd", "3")
	command.ExtraFiles = []*os.File{input}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	must(t, command.Start())
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	defer func() { _ = command.Process.Kill() }()
	_ = input.Close()
	_, err = output.Write(secret)
	must(t, err)
	must(t, output.Close())
	clear(secret)
	select {
	case <-ready:
	case err := <-joined:
		t.Fatalf("installed command exited before dashboard loaded: %v", err)
	case <-bounded.Done():
		t.Fatal("installed dashboard did not load before qualification deadline")
	}
	// The lock is held across the actual child/window lifetime.
	private, err := localfile.OpenDirectory(state, true)
	must(t, err)
	defer private.Close()
	if unix.Flock(int(private.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
		t.Fatal("running installed command released its state lock")
	}
	must(t, command.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-joined:
		if err == nil {
			t.Fatal("cancelled administrator command returned success")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("installed administrator did not join promptly after cancellation")
	}
	must(t, unix.Flock(int(private.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	after, err := os.ReadFile(keyPath)
	must(t, err)
	if !bytes.Equal(original, after) {
		t.Fatal("installed session rewrote encrypted identity")
	}
	must(t, verifyAudit(ctx, f.f.s.db))
	t.Log("unmodified installed CLI and shipped native entrypoint loaded all dashboard assets and authenticated inventory; real kernel clock, secret pipe, held/released state lock, cancellation and unchanged encrypted identity verified")
}

type installedResponse struct {
	http.ResponseWriter
	status int
}

func (w *installedResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
