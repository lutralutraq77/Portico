//go:build linux

package adminkey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type observedSigner struct {
	crypto.Signer
	calls, failures atomic.Int32
}

func (s *observedSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	result, err := s.Signer.Sign(random, digest, opts)
	if err != nil {
		s.failures.Add(1)
	}
	return result, err
}

func TestLinuxEncryptedSignerPersistsAndAuthenticatesTLS(t *testing.T) {
	// Keep the fixture under the checkout's protected ancestors. Shared /tmp
	// directories are intentionally rejected by the production path walker.
	directory, err := os.MkdirTemp(".", ".portico-adminkey-")
	testfixture.Must(t, err)
	directory, err = filepath.Abs(directory)
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "administrator.age")
	pass := []byte("isolated Linux administrator storage fixture")
	defer clear(pass)
	f := keySeed(t)
	first, err := Create(path, f.trust, f.principal, pass)
	testfixture.Must(t, err)
	t.Cleanup(first.Close)
	public := first.Public()
	privateDER, err := x509.MarshalPKCS8PrivateKey(first.private)
	testfixture.Must(t, err)
	defer clear(privateDER)
	original, err := os.ReadFile(path)
	testfixture.Must(t, err)
	if bytes.Contains(original, privateDER) || bytes.Contains(original, pass) || bytes.Contains(original, []byte(f.principal)) {
		t.Fatal("administrator state persisted in plaintext")
	}
	info, err := os.Stat(path)
	testfixture.Must(t, err)
	if info.Mode().Perm() != 0600 {
		t.Fatal("administrator key file is not private")
	}
	if replacement, err := Create(path, f.trust, f.principal, pass); replacement != nil || err != ErrRejected {
		t.Fatal("replaced original administrator key")
	}
	retained, err := os.ReadFile(path)
	testfixture.Must(t, err)
	if !bytes.Equal(retained, original) {
		t.Fatal("failed create changed retained encrypted key")
	}
	first.Close()
	opened, err := Open(path, f.trust, f.principal, pass)
	testfixture.Must(t, err)
	t.Cleanup(opened.Close)
	if !publicEqual(public, opened.Public()) {
		t.Fatal("unlock changed the persisted key")
	}
	csr, err := opened.CSR()
	testfixture.Must(t, err)
	parsed, err := pki.ParseCSR(csr)
	testfixture.Must(t, err)
	identity, err := opened.Identity(f.leaf(t, parsed.PublicKey, f.principal, pki.Administrator))
	testfixture.Must(t, err)
	signer := &observedSigner{Signer: identity.PrivateKey.(crypto.Signer)}
	identity.PrivateKey = signer
	serverRoot, serverRootKey := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, serverRoot, serverRootKey, true)
	var hits atomic.Int32
	var authenticated atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte("encrypted signer fixture"))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAnyClientCert, VerifyConnection: func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
			return ErrRejected
		}
		_, err := f.trust.Verify(state.PeerCertificates[0].Raw, f.principal, time.Now())
		if err == nil {
			authenticated.Add(1)
		}
		return err
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	testfixture.Must(t, err)
	// Use the existing bounded transport allowance. A one-second fixture budget
	// authenticated the key but expired before HTTP under CPU emulation.
	client, err := adminbridge.New(context.Background(), adminbridge.Config{Origin: "https://localhost:" + port, ServerRootDER: serverRoot.Raw, ServerSPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo), AdministratorTrust: f.trust, Identity: identity, BootstrapAddress: server.Listener.Addr().String(), Timeout: 5 * time.Second, Lifetime: time.Minute, ClockHealth: func() (time.Duration, error) { return time.Millisecond, nil }})
	testfixture.Must(t, err)
	t.Cleanup(client.Close)
	started := time.Now()
	r, err := client.Exchange(context.Background(), adminbridge.Request{Method: "GET", Path: "/admin"})
	if err != nil {
		elapsed := time.Since(started)
		sessionClosed := false
		select {
		case <-client.Done():
			sessionClosed = true
		case <-time.After(100 * time.Millisecond):
		}
		t.Fatalf("encrypted-key TLS rejected: elapsed=%s signer_calls=%d signer_failures=%d authenticated=%d requests=%d native_session_closed=%t", elapsed, signer.calls.Load(), signer.failures.Load(), authenticated.Load(), hits.Load(), sessionClosed)
	}
	if r.Status != 200 || string(r.Body) != "encrypted signer fixture" || hits.Load() != 1 || signer.calls.Load() != 1 || signer.failures.Load() != 0 || authenticated.Load() != 1 {
		t.Fatal("retained encrypted key did not authenticate actual TLS")
	}
	opened.Close()
	if _, err := client.Exchange(context.Background(), adminbridge.Request{Method: "GET", Path: "/admin"}); err == nil || hits.Load() != 1 {
		t.Fatal("closed key authenticated a new TLS request")
	}
	client.Close()
	// Each unsafe filesystem mutation below is confined to this new fixture.
	testfixture.Must(t, os.Chmod(path, 0640))
	if k, err := Open(path, f.trust, f.principal, pass); k != nil || err != ErrRejected {
		t.Fatal("group-readable encrypted key accepted")
	}
	testfixture.Must(t, os.Chmod(path, 0600))
	alias := filepath.Join(directory, "alias")
	testfixture.Must(t, os.Symlink(path, alias))
	if k, err := Open(alias, f.trust, f.principal, pass); k != nil || err != ErrRejected {
		t.Fatal("key symlink accepted")
	}
	testfixture.Must(t, os.Remove(alias))
	testfixture.Must(t, os.Link(path, alias))
	if k, err := Open(path, f.trust, f.principal, pass); k != nil || err != ErrRejected {
		t.Fatal("multiply linked key accepted")
	}
	testfixture.Must(t, os.Remove(alias))
	testfixture.Must(t, os.Chmod(directory, 0770))
	if k, err := Open(path, f.trust, f.principal, pass); k != nil || err != ErrRejected {
		t.Fatal("writable parent accepted")
	}
	testfixture.Must(t, os.Chmod(directory, 0700))
	retained, err = os.ReadFile(path)
	testfixture.Must(t, err)
	if !bytes.Equal(retained, original) {
		t.Fatal("rejected unlock changed encrypted state")
	}
	entries, err := os.ReadDir(directory)
	testfixture.Must(t, err)
	if len(entries) != 1 || entries[0].Name() != "administrator.age" {
		t.Fatal("left unexpected key state files")
	}
	t.Log("encrypted state reopened the same key, authenticated actual TLS and rejected a fresh connection after Close; unsafe file paths and modes preserved original state")
}

func publicEqual(a, b any) bool {
	x, xe := x509.MarshalPKIXPublicKey(a)
	y, ye := x509.MarshalPKIXPublicKey(b)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}
