//go:build linux

package adminapp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/adminkey"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestLinuxLoadedKeyAuthenticatesAndIsRevokedOnReturn(t *testing.T) {
	installation, state := installedFixture(t)
	base := filepath.Dir(installation)
	f, files, _, issue := fixture(t)
	// Move the authority fixtures to a protected directory; do not weaken the
	// production reader to accommodate the testing package's shared /tmp root.
	for _, path := range []*string{&f.Administrators.RootCertificateFile, &f.Administrators.IssuerCertificateFile, &f.IdentityCertificateFile} {
		data := files[*path]
		*path = filepath.Join(base, filepath.Base(*path))
		testfixture.Must(t, os.WriteFile(*path, data, 0600))
	}
	f.EncryptedKeyFile = filepath.Join(base, "administrator.age")
	f.StateDirectory = state
	trust, err := identityfile.Reader(localfile.Read).Trust(f.DeploymentID, f.Administrators, pki.Administrator)
	testfixture.Must(t, err)
	passphrase := []byte("isolated application integration passphrase")
	defer clear(passphrase)
	created, err := adminkey.Create(f.EncryptedKeyFile, trust, f.PrincipalID, passphrase)
	testfixture.Must(t, err)
	t.Cleanup(created.Close)
	csrDER, err := created.CSR()
	testfixture.Must(t, err)
	csr, err := pki.ParseCSR(csrDER)
	testfixture.Must(t, err)
	leaf := issue(csr.PublicKey)
	testfixture.Must(t, os.WriteFile(f.IdentityCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), 0600))
	created.Close()
	root, rootKey := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, root, rootKey, true)
	f.Server = identityfile.EndpointFiles{URL: "https://localhost", RootCertificateFile: filepath.Join(base, "server-root.pem"), SPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo)}
	testfixture.Must(t, os.WriteFile(f.Server.RootCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0600))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	testfixture.Must(t, err)
	f.BootstrapAddress = listener.Addr().String()
	activationListener, err := net.Listen("tcp", "127.0.0.1:0")
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = activationListener.Close() })
	f.Version = 2
	f.Renewal = &RenewalFiles{Server: f.Server, BootstrapAddress: activationListener.Addr().String()}
	var authenticated, requests atomic.Int32
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/admin" || r.Host != "localhost" {
			t.Error("request escaped fixed origin or path")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'")
		_, _ = io.WriteString(w, "isolated loaded administrator key")
	})}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) < 1 {
			return ErrRejected
		}
		credential, err := trust.VerifyPeer(s.PeerCertificates[0].Raw, time.Now())
		if err != nil || credential.PrincipalID != f.PrincipalID {
			return ErrRejected
		}
		authenticated.Add(1)
		return nil
	}}
	joined := make(chan struct{})
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)); close(joined) }()
	t.Cleanup(func() { _ = server.Close(); <-joined })
	data, err := json.Marshal(f)
	testfixture.Must(t, err)
	configPath := filepath.Join(base, "admin.json")
	testfixture.Must(t, os.WriteFile(configPath, data, 0600))
	config, err := Load(configPath)
	testfixture.Must(t, err)
	// The guest has no time service. This is an explicit test-only estimate;
	// serialized configuration and the public Run method cannot supply it.
	config.bridge.ClockHealth = func() (time.Duration, error) { return time.Millisecond, nil }
	var retained *adminkey.Key
	open := func(path string, trust *pki.Trust, principal string, pass []byte) (deviceKey, error) {
		retained, err = adminkey.Open(path, trust, principal, pass)
		return retained, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	input := bytes.Clone(passphrase)
	err = config.run(ctx, input, open, func(state string) (adminbridge.Launch, func(), error) { return prepareTree(installation, state) }, func(ctx context.Context, bridge *adminbridge.Client, _ adminbridge.Launch) error {
		response, err := bridge.Exchange(ctx, adminbridge.Request{Method: http.MethodGet, Path: "/admin"})
		if err != nil || response.Status != 200 || string(response.Body) != "isolated loaded administrator key" {
			return ErrRejected
		}
		status, err := bridge.Exchange(ctx, adminbridge.Request{Method: http.MethodPost, Path: adminrenewal.StatusPath, Origin: config.bridge.Origin, Body: []byte(`{"Version":1}`)})
		if err != nil || status.Status != http.StatusOK {
			return ErrRejected
		}
		var renewal adminrenewal.Status
		if json.Unmarshal(status.Body, &renewal) != nil || renewal.Version != 1 || renewal.State != "ready" || renewal.CurrentCertificateHash != pki.Hash(leaf) {
			return ErrRejected
		}
		if other, err := openCredentialDisk(state); err == nil || other != nil {
			t.Fatal("running version-2 command did not retain the credential directory lock")
		}
		return nil
	})
	testfixture.Must(t, err)
	if authenticated.Load() != 1 || requests.Load() != 1 || retained == nil || retained.Public() != nil || !bytes.Equal(input, make([]byte, len(input))) {
		t.Fatal("loaded key did not authenticate exactly once or was retained")
	}
	if _, err := retained.Identity(leaf); err != adminkey.ErrRejected {
		t.Fatal("returned session retained usable key")
	}
	_, release, err := prepareTree(installation, state)
	testfixture.Must(t, err)
	release()
	disk, err := openCredentialDisk(state)
	testfixture.Must(t, err)
	defer disk.Close()
	journal, err := openCredentialJournal(config, disk)
	testfixture.Must(t, err)
	if !bytes.Equal(journal.record.Certificate, leaf) || journal.record.Pending != nil {
		t.Fatal("version-2 command did not retain its selected public identity")
	}
	t.Log("protected version-2 configuration, encrypted key reopen, actual pinned administrator TLS, durable credential status, consumed passphrase, revoked signer and released state/credential locks verified; native child execution is qualified separately")
}
