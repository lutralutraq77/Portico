package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type clientFixture struct {
	config         Config
	request        RedeemRequest
	key, issuerKey *ecdsa.PrivateKey
	issuer         *x509.Certificate
	identity       tls.Certificate
	root           *x509.Certificate
	serverIdentity tls.Certificate
}

func newClientFixture(t *testing.T) *clientFixture {
	t.Helper()
	root, rk := testfixture.Root(t)
	ik := testfixture.Key(t)
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	trust, err := pki.NewTrust(pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: pki.Device, RootDER: root.Raw, IssuerDER: issuer.Raw})
	testfixture.Must(t, err)
	key := testfixture.Key(t)
	r, err := NewRequest(uuid.NewString(), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), uuid.NewString(), key)
	testfixture.Must(t, err)
	f := &clientFixture{config: Config{Trust: trust, PrincipalID: uuid.NewString(), NotAfter: time.Now().UTC().Truncate(time.Second).Add(time.Hour), Timeout: 5 * time.Second, MaxRequests: 1}, request: r, key: key, issuerKey: ik, issuer: issuer, root: root, serverIdentity: testfixture.TLSIdentity(t, root, rk, true)}
	f.identity = tls.Certificate{Certificate: [][]byte{f.leaf(t, f.config.PrincipalID, key, f.config.NotAfter)}, PrivateKey: key}
	return f
}

func (f *clientFixture) leaf(t *testing.T, principal string, key *ecdsa.PrivateKey, until time.Time) []byte {
	t.Helper()
	uri, err := pki.IdentityURI(f.config.Trust.DeploymentID(), pki.Device, principal)
	testfixture.Must(t, err)
	return testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{uri}}, f.issuer, &key.PublicKey, f.issuerKey).Raw
}

func (f *clientFixture) serve(t *testing.T, handler http.HandlerFunc) Endpoint {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.serverIdentity}, ClientAuth: tls.RequestClientCert, SessionTicketsDisabled: true}
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return Endpoint{URL: strings.Replace(s.URL, "127.0.0.1", "localhost", 1), ServerRootDER: f.root.Raw, ServerSPKI: pki.Hash(f.serverIdentity.Leaf.RawSubjectPublicKeyInfo)}
}

func (f *clientFixture) client(t *testing.T, e Endpoint) *Client {
	t.Helper()
	cfg := f.config
	cfg.Redemption = e
	cfg.Activation = e
	cfg.Activation.URL = "https://localhost:1"
	c, err := New(cfg)
	testfixture.Must(t, err)
	t.Cleanup(c.Close)
	return c
}

func TestClientRejectsIncorrectResponses(t *testing.T) {
	f := newClientFixture(t)
	good := CertificateResponse{Version: Version, InvitationID: f.request.InvitationID, AttemptID: f.request.AttemptID, CertificateDER: f.identity.Certificate[0]}
	tests := []struct {
		name   string
		change func(*CertificateResponse)
		body   string
		header string
	}{
		{name: "version", change: func(r *CertificateResponse) { r.Version = 2 }},
		{name: "invitation", change: func(r *CertificateResponse) { r.InvitationID = uuid.NewString() }},
		{name: "attempt", change: func(r *CertificateResponse) { r.AttemptID = uuid.NewString() }},
		{name: "principal", change: func(r *CertificateResponse) { r.CertificateDER = f.leaf(t, uuid.NewString(), f.key, f.config.NotAfter) }},
		{name: "key", change: func(r *CertificateResponse) {
			r.CertificateDER = f.leaf(t, f.config.PrincipalID, testfixture.Key(t), f.config.NotAfter)
		}},
		{name: "expiry", change: func(r *CertificateResponse) {
			r.CertificateDER = f.leaf(t, f.config.PrincipalID, f.key, f.config.NotAfter.Add(time.Second))
		}},
		{name: "missing-leaf", change: func(r *CertificateResponse) { r.CertificateDER = nil }},
		{name: "non-object", body: "[]"},
		{name: "oversized", body: strings.Repeat(" ", MaxBody+1)},
		{name: "compressed", header: "gzip"},
		{name: "unknown-field", body: `{"Version":1,"Profile":"administrator"}`},
		{name: "duplicate", body: `{"Version":1,"Version":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			if tc.change != nil {
				tc.change(&r)
			}
			e := f.serve(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.header != "" {
					w.Header().Set("Content-Encoding", tc.header)
				}
				if tc.body != "" {
					_, _ = io.WriteString(w, tc.body)
				} else {
					_ = json.NewEncoder(w).Encode(r)
				}
			})
			if _, err := f.client(t, e).Redeem(context.Background(), f.request, f.key); err != ErrRejected {
				t.Fatalf("incorrect response accepted or leaked details: %v", err)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		e := f.serve(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != RedeemPath || len(r.TLS.PeerCertificates) != 0 {
				t.Error("redemption sent a client identity or wrong route")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(good)
		})
		identity, err := f.client(t, e).Redeem(context.Background(), f.request, f.key)
		testfixture.Must(t, err)
		if !bytes.Equal(identity.Certificate[0], good.CertificateDER) {
			t.Fatal("changed certificate")
		}
	})
}

func TestClientServerTrustVerifiedBeforeSendingSecret(t *testing.T) {
	for _, kind := range []string{"pin", "root", "hostname"} {
		t.Run(kind, func(t *testing.T) {
			f := newClientFixture(t)
			var calls atomic.Int32
			e := f.serve(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			switch kind {
			case "pin":
				e.ServerSPKI = strings.Repeat("0", 64)
			case "root":
				root, _ := testfixture.Root(t)
				e.ServerRootDER = root.Raw
			case "hostname":
				e.URL = strings.Replace(e.URL, "localhost", "127.0.0.1", 1)
			}
			if _, err := f.client(t, e).Redeem(context.Background(), f.request, f.key); err != ErrRejected {
				t.Fatalf("untrusted server accepted: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("invitation sent before server authentication")
			}
		})
	}
}

func TestClientDoesNotFollowRedirectOrSendMismatchedProof(t *testing.T) {
	f := newClientFixture(t)
	var targetCalls, sourceCalls atomic.Int32
	target := f.serve(t, func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) })
	source := f.serve(t, func(w http.ResponseWriter, r *http.Request) {
		sourceCalls.Add(1)
		http.Redirect(w, r, target.URL+RedeemPath, http.StatusTemporaryRedirect)
	})
	c := f.client(t, source)
	if _, err := c.Redeem(context.Background(), f.request, testfixture.Key(t)); err != ErrRejected || sourceCalls.Load() != 0 {
		t.Fatal("mismatched key reached server")
	}
	if _, err := c.Redeem(context.Background(), f.request, f.key); err != ErrRejected || sourceCalls.Load() != 1 || targetCalls.Load() != 0 {
		t.Fatal("redirect followed or request replayed")
	}
}

func TestClientCloseCancelsAndJoinsRequests(t *testing.T) {
	f := newClientFixture(t)
	entered, left := make(chan struct{}), make(chan struct{})
	e := f.serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(left)
	})
	c := f.client(t, e)
	done := make(chan error, 1)
	go func() { _, err := c.Redeem(context.Background(), f.request, f.key); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request not started")
	}
	if _, err := c.Redeem(context.Background(), f.request, f.key); err != ErrRejected {
		t.Fatal("request bound exceeded")
	}
	c.Close()
	select {
	case err := <-done:
		if err != ErrRejected {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request not joined")
	}
	select {
	case <-left:
	case <-time.After(time.Second):
		t.Fatal("server did not observe cancellation")
	}
	if _, err := c.Redeem(context.Background(), f.request, f.key); err != ErrRejected {
		t.Fatal("closed client accepted request")
	}
}

func TestClientActivationRequiresExactReceiptAndFreshTLSIdentity(t *testing.T) {
	f := newClientFixture(t)
	for _, good := range []bool{false, true} {
		t.Run(map[bool]string{false: "wrong-receipt", true: "valid"}[good], func(t *testing.T) {
			e := f.serve(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != ActivatePath || r.TLS.DidResume || len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, f.identity.Certificate[0]) {
					t.Error("activation lacks fresh TLS identity")
				}
				id := f.request.InvitationID
				if !good {
					id = uuid.NewString()
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(Activated{Version: Version, InvitationID: id})
			})
			cfg := f.config
			cfg.Activation = e
			cfg.Redemption = e
			cfg.Redemption.URL = "https://localhost:1"
			c, err := New(cfg)
			testfixture.Must(t, err)
			t.Cleanup(c.Close)
			err = c.Activate(context.Background(), f.request.InvitationID, f.identity)
			if (err == nil) != good {
				t.Fatalf("activation result: %v", err)
			}
		})
	}
}

func TestRequestBodyCancellationPreservesReadBytesAndErasesSource(t *testing.T) {
	// A cancelled HTTP upload may read/close the body after Do returns. Race
	// instrumentation must see neither concurrent erasure nor torn copied bytes.
	for i := 0; i < 64; i++ {
		data := bytes.Repeat([]byte{0xa5}, MaxBody)
		b := &requestBody{data: data}
		ready := make(chan struct{})
		firstRead := make(chan struct{})
		var work sync.WaitGroup
		work.Add(1)
		go func() {
			defer work.Done()
			<-ready
			var chunk [37]byte
			started := false
			for {
				n, err := b.Read(chunk[:])
				if !started {
					started = true
					close(firstRead)
				}
				for _, v := range chunk[:n] {
					if v != 0xa5 {
						t.Error("upload received bytes modified by cleanup")
						return
					}
				}
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
		close(ready)
		<-firstRead
		testfixture.Must(t, b.Close())
		work.Wait()
		if !bytes.Equal(data, make([]byte, MaxBody)) {
			t.Fatal("request source was not erased")
		}
		var p [1]byte
		if n, err := b.Read(p[:]); n != 0 || err != io.EOF {
			t.Fatal("closed body resumed upload")
		}
		testfixture.Must(t, b.Close())
	}
}
