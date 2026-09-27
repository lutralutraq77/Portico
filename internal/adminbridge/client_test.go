package adminbridge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// The transport receives only crypto.Signer, as an OS key provider would expose.
// Counting real TLS signatures proves that a reused browser request cannot bypass
// device possession. This remains a software fixture, not OS key qualification.
type countedSigner struct {
	crypto.Signer
	signs atomic.Int32
}

func (s *countedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signs.Add(1)
	return s.Signer.Sign(r, digest, opts)
}

type bridgeFixture struct {
	config Config
	server *httptest.Server
	signer *countedSigner
	hits   atomic.Int32
}

func bridgeSeed(t *testing.T, handler http.HandlerFunc) *bridgeFixture {
	t.Helper()
	f := &bridgeFixture{}
	root, rk := testfixture.Root(t)
	ik := testfixture.Key(t)
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated admin issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	trust, err := pki.NewTrust(pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: pki.Administrator, RootDER: root.Raw, IssuerDER: issuer.Raw})
	testfixture.Must(t, err)
	key := testfixture.Key(t)
	u, err := pki.IdentityURI(trust.DeploymentID(), pki.Administrator, uuid.NewString())
	testfixture.Must(t, err)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, issuer, &key.PublicKey, ik)
	f.signer = &countedSigner{Signer: key}
	serverRoot, serverKey := testfixture.Root(t)
	identity := testfixture.TLSIdentity(t, serverRoot, serverKey, true)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if handler != nil {
			handler(w, r)
		} else {
			_, _ = w.Write([]byte("<p>private</p>"))
		}
	}))
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert, Certificates: []tls.Certificate{identity}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return ErrRejected
		}
		_, err := trust.VerifyPeer(state.PeerCertificates[0].Raw, time.Now())
		return err
	}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	_, port, err := net.SplitHostPort(f.server.Listener.Addr().String())
	testfixture.Must(t, err)
	f.config = Config{Origin: "https://localhost:" + port, ServerSPKI: pki.Hash(identity.Leaf.RawSubjectPublicKeyInfo), ServerRootDER: serverRoot.Raw, AdministratorTrust: trust, Identity: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: f.signer}, BootstrapAddress: f.server.Listener.Addr().String(), Timeout: time.Second, Lifetime: time.Minute, ClockHealth: func() (time.Duration, error) { return 0, nil }}
	return f
}

func (f *bridgeFixture) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(context.Background(), f.config)
	testfixture.Must(t, err)
	t.Cleanup(c.Close)
	return c
}

func TestCanonicalOrigin(t *testing.T) {
	for _, value := range []string{"https://admin.portico.test", "https://admin.portico.test:8443", "https://127.0.0.1:8443", "https://[::1]:8443"} {
		if !Origin(value) {
			t.Errorf("canonical origin rejected: %q", value)
		}
	}
	for _, value := range []string{"http://admin.portico.test", "https://Admin.portico.test", "https://admin.portico.test/", "https://admin.portico.test:443", "https://admin.portico.test:08443", "https://admin.portico.test:", "https://admin.portico.test.", "https://admin.portico.test?", "https://a@admin.portico.test", "https://é.test", "https://-a.test", "https://a..test", "https://a_.test", "https://127.1", "https://0177.0.0.1", "https://0x7f000001", "https://[0:0:0:0:0:0:0:1]", "https://[::1%25eth0]"} {
		if Origin(value) {
			t.Errorf("ambiguous origin accepted: %q", value)
		}
	}
}

func TestNativeTLSAndRequestBoundary(t *testing.T) {
	f := bridgeSeed(t, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("TLS/request boundary violated")
		}
		if r.Method == "POST" {
			if r.Header.Get("Origin") != "https://"+r.Host || r.Header.Get("Content-Type") != "application/json" {
				t.Error("origin/header mismatch")
			}
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write([]byte("{}"))
	})
	c := f.client(t)
	for _, request := range []Request{{Method: "GET", Path: "/admin"}, {Method: "POST", Path: "/api/v1/admin/dashboard/inventory", Origin: c.Origin(), Site: "same-origin", Body: []byte(`{"section":"users"}`)}} {
		response, err := c.Exchange(context.Background(), request)
		testfixture.Must(t, err)
		if response.Status != 200 || string(response.Body) != "{}" {
			t.Fatal("response changed")
		}
	}
	if f.signer.signs.Load() != 2 || f.hits.Load() != 2 {
		t.Fatal("each request must freshly prove the administrator key")
	}
	for _, request := range []Request{
		{Method: "GET", Path: "/admin?override=1"}, {Method: "GET", Path: "https://foreign.test/admin"}, {Method: "GET", Path: "/%61dmin"}, {Method: "GET", Path: "/admin", Site: "cross-site"}, {Method: "GET", Path: "/admin", Origin: "https://foreign.test"}, {Method: "GET", Path: "/admin", Body: []byte("{}")}, {Method: "DELETE", Path: "/admin"},
		{Method: "POST", Path: "/api/v1/admin/dashboard/inventory", Body: []byte("{}")}, {Method: "POST", Path: "/api/v1/device/catalog", Origin: c.Origin(), Body: []byte("{}")}, {Method: "POST", Path: "/api/v1/admin/dashboard/inventory", Origin: c.Origin(), Body: []byte(`{"a":1,"A":2}`)}, {Method: "POST", Path: "/api/v1/admin/dashboard/inventory", Origin: c.Origin(), Body: bytes.Repeat([]byte(" "), 65537)},
	} {
		if _, err := c.Exchange(context.Background(), request); err == nil {
			t.Errorf("unsafe request accepted: %s %s", request.Method, request.Path)
		}
	}
	if f.hits.Load() != 2 || f.signer.signs.Load() != 2 {
		t.Fatal("rejected request reached the network")
	}
	c.Close()
	if _, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"}); err == nil {
		t.Fatal("closed channel retained authority")
	}
}

func TestNativeServerAuthentication(t *testing.T) {
	for _, scenario := range []string{"wrong_pin", "wrong_root", "wrong_hostname", "tls12"} {
		t.Run(scenario, func(t *testing.T) {
			f := bridgeSeed(t, nil)
			switch scenario {
			case "wrong_pin":
				f.config.ServerSPKI = strings.Repeat("0", 64)
			case "wrong_root":
				root, _ := testfixture.Root(t)
				f.config.ServerRootDER = root.Raw
			case "wrong_hostname":
				f.config.Origin = strings.Replace(f.config.Origin, "localhost", "foreign.test", 1)
			case "tls12":
				f.server.TLS.MaxVersion = tls.VersionTLS12
			}
			if _, err := f.client(t).Exchange(context.Background(), Request{Method: "GET", Path: "/admin"}); err == nil {
				t.Fatal("untrusted server accepted")
			}
			if f.hits.Load() != 0 {
				t.Fatal("request disclosed to untrusted server")
			}
		})
	}
}

func TestNativeResponseBoundary(t *testing.T) {
	for _, scenario := range []string{"redirect", "cookie", "encoding", "download", "cache", "mime", "frame", "referrer", "duplicate_csp", "weak_csp", "duplicate_mime", "oversized", "partial", "lost_confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			f := bridgeSeed(t, func(w http.ResponseWriter, r *http.Request) {
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "/admin")
					w.WriteHeader(302)
				case "cookie":
					w.Header().Set("Set-Cookie", "a=b")
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "download":
					w.Header().Set("Content-Disposition", "attachment")
				case "cache":
					w.Header().Set("Cache-Control", "public")
				case "mime":
					w.Header().Set("Content-Type", "application/octet-stream")
				case "frame":
					w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				case "referrer":
					w.Header().Set("Referrer-Policy", "origin")
				case "duplicate_csp":
					w.Header().Add("Content-Security-Policy", "default-src *")
				case "weak_csp":
					w.Header().Set("Content-Security-Policy", "default-src *")
				case "duplicate_mime":
					w.Header().Add("Content-Type", "text/javascript")
				case "oversized":
					_, _ = w.Write(bytes.Repeat([]byte("x"), MaxResponse+1))
				case "partial":
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte("partial"))
				case "lost_confirmation":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
				}
			})
			c := f.client(t)
			r := Request{Method: "GET", Path: "/admin"}
			if scenario == "lost_confirmation" {
				r = Request{Method: "POST", Path: "/api/v1/admin/policy/confirm", Origin: c.Origin(), Body: []byte("{}")}
			}
			response, err := c.Exchange(context.Background(), r)
			if err == nil || len(response.Body) != 0 || response.Status != 0 {
				t.Fatal("invalid/uncertain response exposed")
			}
			if f.hits.Load() != 1 {
				t.Fatal("request was replayed")
			}
		})
	}
}

func TestNativeCancellationAndAdmission(t *testing.T) {
	entered := make(chan struct{}, 4)
	f := bridgeSeed(t, func(_ http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() })
	f.config.Timeout = 5 * time.Second
	c := f.client(t)
	completed := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			_, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"})
			completed <- err
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("request did not reach server")
		}
	}
	start := time.Now()
	if _, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"}); err == nil {
		t.Fatal("fifth concurrent request admitted")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("admission queued excess request")
	}
	c.Close()
	for i := 0; i < 4; i++ {
		select {
		case err := <-completed:
			if err == nil {
				t.Fatal("cancelled request succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("request survived native channel closure")
		}
	}
	if f.hits.Load() != 4 {
		t.Fatal("unexpected request count")
	}
}

func TestNativeConfigurationAndLifetime(t *testing.T) {
	f := bridgeSeed(t, nil)
	for _, scenario := range []string{"no_trust", "no_identity", "mismatched_key", "bad_pin", "uppercase_pin", "no_root", "no_destination", "two_destinations", "remote_destination", "named_destination", "mapped_destination", "unbounded_timeout", "unbounded_lifetime"} {
		t.Run(scenario, func(t *testing.T) {
			config := f.config
			switch scenario {
			case "no_trust":
				config.AdministratorTrust = nil
			case "no_identity":
				config.Identity = tls.Certificate{}
			case "mismatched_key":
				config.Identity.PrivateKey = testfixture.Key(t)
			case "bad_pin":
				config.ServerSPKI = "invalid"
			case "uppercase_pin":
				config.ServerSPKI = strings.ToUpper(config.ServerSPKI)
			case "no_root":
				config.ServerRootDER = nil
			case "no_destination":
				config.BootstrapAddress = ""
			case "two_destinations":
				config.Socket = "/private/socket"
			case "remote_destination":
				config.BootstrapAddress = "192.0.2.1:443"
			case "named_destination":
				config.BootstrapAddress = "localhost:443"
			case "mapped_destination":
				config.BootstrapAddress = "[::ffff:127.0.0.1]:443"
			case "unbounded_timeout":
				config.Timeout = 6 * time.Second
			case "unbounded_lifetime":
				config.Lifetime = 11 * time.Minute
			}
			c, err := New(context.Background(), config)
			if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("unsafe native configuration accepted")
			}
		})
	}
	f.config.Lifetime = 50 * time.Millisecond
	c := f.client(t)
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("native lifetime did not end")
	}
	if _, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"}); err == nil {
		t.Fatal("expired native session retained authority")
	}
	if f.hits.Load() != 0 {
		t.Fatal("invalid or expired configuration reached server")
	}
}
