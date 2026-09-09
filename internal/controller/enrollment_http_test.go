package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	enroll "portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type enrollmentHTTPFixture struct {
	f                      *enrollmentFixture
	client                 *enroll.Client
	config                 enroll.Config
	redemption, activation *EnrollmentHTTPServer
}

func enrollmentHTTP(t *testing.T, f *enrollmentFixture, provider IssuanceProvider) *enrollmentHTTPFixture {
	t.Helper()
	root, rk := testfixture.Root(t)
	server := testfixture.TLSIdentity(t, root, rk, true)
	v := &enrollmentHTTPFixture{f: f}
	endpoints := make([]enroll.Endpoint, 2)
	for i := range endpoints {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		must(t, err)
		host := net.JoinHostPort("localhost", strings.Split(l.Addr().String(), ":")[1])
		cfg := EnrollmentHTTPConfig{Host: host, ServerIdentity: server, Trust: f.trust, Timeout: 5 * time.Second, MaxConnections: 4, MaxRequests: 2}
		var s *EnrollmentHTTPServer
		if i == 0 {
			cfg.Provider = provider
			s, err = f.f.s.NewEnrollmentRedemptionServer(cfg)
			v.redemption = s
		} else {
			s, err = f.f.s.NewEnrollmentActivationServer(cfg)
			v.activation = s
		}
		must(t, err)
		done := make(chan error, 1)
		go func() { done <- s.Serve(l) }()
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			must(t, s.Close(stop))
			select {
			case err := <-done:
				if !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("server exit: %v", err)
				}
			case <-stop.Done():
				t.Error("server did not join")
			}
			if got := s.Stats(); got.Connections != 0 || got.Requests != 0 {
				t.Errorf("server ownership not drained: %+v", got)
			}
		})
		endpoints[i] = enroll.Endpoint{URL: "https://" + host, ServerRootDER: root.Raw, ServerSPKI: pki.Hash(server.Leaf.RawSubjectPublicKeyInfo)}
	}
	principal := f.f.device.ID
	if f.trust.Profile() == pki.Connector {
		principal = f.f.connector.ID
	}
	v.config = enroll.Config{Redemption: endpoints[0], Activation: endpoints[1], Trust: f.trust, PrincipalID: principal, NotAfter: f.f.s.now().Add(time.Hour), Timeout: 5 * time.Second, MaxRequests: 2}
	var err error
	v.client, err = enroll.New(v.config)
	must(t, err)
	t.Cleanup(v.client.Close)
	return v
}

func enrollmentRequest(t *testing.T, v invited) enroll.RedeemRequest {
	t.Helper()
	r, err := enroll.NewRequest(v.id, v.secret, v.attempt, v.key)
	must(t, err)
	return r
}

func enrollmentRaw(t *testing.T, endpoint enroll.Endpoint, identity *tls.Certificate, data []byte, change func(*http.Request)) (int, []byte) {
	t.Helper()
	root := x509.NewCertPool()
	root.AddCert(parseCert(t, endpoint.ServerRootDER))
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: root}
	if identity != nil {
		tc.Certificates = []tls.Certificate{*identity}
	}
	transport := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, Proxy: nil}
	defer transport.CloseIdleConnections()
	h := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	r, err := http.NewRequest(http.MethodPost, endpoint.URL+enroll.RedeemPath, bytes.NewReader(data))
	must(t, err)
	r.Header.Set("Content-Type", "application/json")
	if change != nil {
		change(r)
	}
	res, err := h.Do(r)
	if err != nil {
		return 0, nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	must(t, err)
	return res.StatusCode, body
}

func TestEnrollmentHTTPRedemptionActivationAndRetry(t *testing.T) {
	f := enrollmentSeed(t)
	h := enrollmentHTTP(t, f, f.provider(t))
	v := f.invite(t)
	identity, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	if _, err = tlsHandshake(t, f.f.s, f.trust, identity, false); err == nil {
		t.Fatal("pending credential authenticated")
	}
	if err = h.client.Activate(ctx, NewID(), identity); err == nil {
		t.Fatal("credential activated another invitation")
	}
	must(t, h.client.Activate(ctx, v.id, identity))
	must(t, h.client.Activate(ctx, v.id, identity))
	_, err = tlsHandshake(t, f.f.s, f.trust, identity, false)
	must(t, err)
	retried, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	if !bytes.Equal(identity.Certificate[0], retried.Certificate[0]) || f.calls.Load() != 1 {
		t.Fatal("retry changed certificate or signed again")
	}
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(v.id) }))
	if err = h.client.Activate(ctx, v.id, identity); err == nil {
		t.Fatal("revoked certificate activated")
	}
	if _, err = h.client.Redeem(ctx, enrollmentRequest(t, v), v.key); err == nil {
		t.Fatal("revoked certificate retrieved")
	}
	if f.calls.Load() != 1 {
		t.Fatal("revocation caused another signing call")
	}
}

func TestEnrollmentHTTPRejectsRequestAuthorityAndRoutes(t *testing.T) {
	f := enrollmentSeed(t)
	h := enrollmentHTTP(t, f, f.provider(t))
	v := f.invite(t)
	b, err := json.Marshal(enrollmentRequest(t, v))
	must(t, err)
	cases := []struct {
		name   string
		body   []byte
		change func(*http.Request)
	}{
		{"unknown-profile", append(append([]byte{}, b[:len(b)-1]...), []byte(`,"Profile":"administrator"}`)...), nil},
		{"caller-expiry", append(append([]byte{}, b[:len(b)-1]...), []byte(`,"NotAfter":"2099-01-01T00:00:00Z"}`)...), nil},
		{"old-version", bytes.Replace(b, []byte(`"Version":1`), []byte(`"Version":0`), 1), nil},
		{"duplicate", append(append([]byte{}, b[:len(b)-1]...), []byte(`,"Version":1}`)...), nil},
		{"oversized", bytes.Repeat([]byte(" "), enroll.MaxBody+1), nil},
		{"wrong-secret", bytes.Replace(b, []byte(v.secret), []byte(strings.Repeat("A", 43)), 1), nil},
		{"route", b, func(r *http.Request) { r.URL.Path = "/sign" }},
		{"query", b, func(r *http.Request) { r.URL.RawQuery = "profile=administrator" }},
		{"empty-query", b, func(r *http.Request) { r.URL.ForceQuery = true }},
		{"host", b, func(r *http.Request) { r.Host = "other.localhost:443" }},
		{"method", b, func(r *http.Request) { r.Method = http.MethodGet }},
		{"origin", b, func(r *http.Request) { r.Header.Set("Origin", "https://localhost") }},
		{"cookie", b, func(r *http.Request) { r.Header.Set("Cookie", "session=fixture") }},
		{"authorization", b, func(r *http.Request) { r.Header.Set("Authorization", "Bearer fixture") }},
		{"compressed", b, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
	}
	before := summary(t, f.f.s)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := enrollmentRaw(t, h.config.Redemption, nil, tc.body, tc.change)
			if status != http.StatusForbidden || string(body) != `{"error":"request rejected"}` {
				t.Fatalf("not a generic denial: %d %s", status, body)
			}
			if f.calls.Load() != 0 || summary(t, f.f.s) != before {
				t.Fatal("denial mutated authority or invoked provider")
			}
		})
	}
	// A real certificate is insufficient without its private-key TLS proof.
	identity, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	a, err := json.Marshal(enroll.ActivateRequest{Version: 1, InvitationID: v.id})
	must(t, err)
	status, _ := enrollmentRaw(t, h.config.Activation, nil, a, func(r *http.Request) {
		r.URL.Path = enroll.ActivatePath
		r.Header.Set("X-Client-Cert", base64.StdEncoding.EncodeToString(identity.Certificate[0]))
	})
	if status != 0 {
		t.Fatalf("anonymous activation passed TLS: %d", status)
	}
}

func TestEnrollmentHTTPWrongIssuerDoesNotConsumeInvitation(t *testing.T) {
	d := enrollmentSeed(t)
	c := connectorPolicyFixture(t, d)
	h := enrollmentHTTP(t, d, d.provider(t))
	id := NewID()
	secret, err := d.f.s.Invite(ctx, d.f.actor, InvitationSpec{ID: id, IssuerID: c.trust.IssuerID(), PrincipalID: c.f.connector.ID, Profile: pki.Connector, ExpiresAt: d.f.s.now().Add(5 * time.Minute), NotAfter: d.f.s.now().Add(time.Hour)})
	must(t, err)
	v := invited{id: id, secret: secret, attempt: NewID(), key: newKey(t)}
	before := summary(t, d.f.s)
	if _, err = h.client.Redeem(ctx, enrollmentRequest(t, v), v.key); err == nil {
		t.Fatal("device endpoint accepted connector invitation")
	}
	if d.calls.Load() != 0 || summary(t, d.f.s) != before {
		t.Fatal("wrong issuer consumed invitation")
	}
	// The correct profile must still work after the incorrect endpoint denied it.
	correct := enrollmentHTTP(t, c, c.provider(t))
	identity, err := correct.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	must(t, correct.client.Activate(ctx, v.id, identity))
	if c.calls.Load() != 1 {
		t.Fatal("connector issuance count")
	}
}

func TestEnrollmentHTTPAmbiguousIssueRequiresReconciliation(t *testing.T) {
	f := enrollmentSeed(t)
	results := make(chan []byte, 1)
	h := enrollmentHTTP(t, f, issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
		results <- f.sign(t, r)
		return nil, errors.New("lost response")
	}))
	v := f.invite(t)
	for i := 0; i < 2; i++ {
		if _, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key); err == nil {
			t.Fatal("ambiguous signing returned certificate")
		}
	}
	if f.calls.Load() != 1 {
		t.Fatal("uncertain attempt signed twice")
	}
	result := <-results
	must(t, f.f.s.ReconcileEnrollment(ctx, f.f.actor, v.id, f.trust, result))
	identity, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	must(t, h.client.Activate(ctx, v.id, identity))
	if !bytes.Equal(identity.Certificate[0], result) || f.calls.Load() != 1 {
		t.Fatal("reconciliation changed issued result")
	}
}

func TestEnrollmentHTTPConcurrentRedemptionDoesNotResign(t *testing.T) {
	f := enrollmentSeed(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := enrollmentHTTP(t, f, issueFunc(func(c context.Context, r IssuanceRequest) ([]byte, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return f.sign(t, r), nil
		case <-c.Done():
			return nil, c.Err()
		}
	}))
	v := f.invite(t)
	request := enrollmentRequest(t, v)
	done := make(chan error, 1)
	go func() { _, err := h.client.Redeem(ctx, request, v.key); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider not entered")
	}
	if _, err := h.client.Redeem(ctx, request, v.key); err == nil {
		t.Fatal("concurrent issuing request succeeded")
	}
	close(release)
	must(t, <-done)
	_, err := h.client.Redeem(ctx, request, v.key)
	must(t, err)
	if f.calls.Load() != 1 {
		t.Fatal("concurrent redemption signed twice")
	}
}

func TestEnrollmentHTTPShutdownCancelsProviderAndDrains(t *testing.T) {
	f := enrollmentSeed(t)
	entered, left := make(chan struct{}), make(chan struct{})
	h := enrollmentHTTP(t, f, issueFunc(func(c context.Context, _ IssuanceRequest) ([]byte, error) {
		close(entered)
		<-c.Done()
		close(left)
		return nil, c.Err()
	}))
	v := f.invite(t)
	r := enrollmentRequest(t, v)
	done := make(chan error, 1)
	go func() { _, err := h.client.Redeem(ctx, r, v.key); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider not entered")
	}
	stop, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	must(t, h.redemption.Close(stop))
	select {
	case <-left:
	default:
		t.Fatal("provider not joined")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled issuance succeeded")
		}
	case <-stop.Done():
		t.Fatal("client did not return")
	}
	if got := h.redemption.Stats(); got.Connections != 0 || got.Requests != 0 {
		t.Fatalf("not drained: %+v", got)
	}
}

func TestEnrollmentHTTPRejectsClaimedCSRAndChangedReservation(t *testing.T) {
	f := enrollmentSeed(t)
	h := enrollmentHTTP(t, f, f.provider(t))
	v := f.invite(t)
	before := summary(t, f.f.s)
	for _, template := range []*x509.CertificateRequest{
		{Subject: pkix.Name{CommonName: "administrator"}},
		{DNSNames: []string{"localhost"}},
	} {
		request := enrollmentRequest(t, v)
		var err error
		request.CSR, err = x509.CreateCertificateRequest(rand.Reader, template, v.key)
		must(t, err)
		body, err := json.Marshal(request)
		must(t, err)
		status, _ := enrollmentRaw(t, h.config.Redemption, nil, body, nil)
		if status != http.StatusForbidden || f.calls.Load() != 0 || summary(t, f.f.s) != before {
			t.Fatal("CSR claims changed enrollment or reached provider")
		}
	}
	_, err := h.client.Redeem(ctx, enrollmentRequest(t, v), v.key)
	must(t, err)
	before = summary(t, f.f.s)
	for _, changed := range []invited{
		{id: v.id, secret: v.secret, attempt: NewID(), key: v.key},
		{id: v.id, secret: v.secret, attempt: v.attempt, key: newKey(t)},
	} {
		if _, err := h.client.Redeem(ctx, enrollmentRequest(t, changed), changed.key); err == nil {
			t.Fatal("changed reservation accepted")
		}
		if f.calls.Load() != 1 || summary(t, f.f.s) != before {
			t.Fatal("changed reservation mutated authority or signed again")
		}
	}
}

func TestEnrollmentHTTPRejectsExcessRequestsWithoutQueue(t *testing.T) {
	f := enrollmentSeed(t)
	entered := make(chan struct{}, 2)
	var calls atomic.Int32
	h := enrollmentHTTP(t, f, issueFunc(func(c context.Context, _ IssuanceRequest) ([]byte, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-c.Done()
		return nil, c.Err()
	}))
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		v := f.invite(t)
		r := enrollmentRequest(t, v)
		go func() { _, err := h.client.Redeem(ctx, r, v.key); done <- err }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("admitted provider not entered")
		}
	}
	third := f.invite(t)
	b, err := json.Marshal(enrollmentRequest(t, third))
	must(t, err)
	before := summary(t, f.f.s)
	status, _ := enrollmentRaw(t, h.config.Redemption, nil, b, nil)
	if status != http.StatusForbidden || calls.Load() != 2 || h.redemption.Stats().Requests != 2 || summary(t, f.f.s) != before {
		t.Fatal("request capacity overflow was queued or mutated authority")
	}
	stop, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	must(t, h.redemption.Close(stop))
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancelled request succeeded")
			}
		case <-stop.Done():
			t.Fatal("cancelled request did not join")
		}
	}
}

func TestEnrollmentHTTPBoundsUnauthenticatedConnections(t *testing.T) {
	f := enrollmentSeed(t)
	h := enrollmentHTTP(t, f, f.provider(t))
	u, err := url.Parse(h.config.Redemption.URL)
	must(t, err)
	address := net.JoinHostPort("127.0.0.1", u.Port())
	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := net.DialTimeout("tcp4", address, time.Second)
		must(t, err)
		held = append(held, c)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.redemption.Stats().Connections != 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := h.redemption.Stats(); got.Connections != 4 || got.Requests != 0 {
		t.Fatalf("unexpected admission: %+v", got)
	}
	overflow, err := net.DialTimeout("tcp4", address, time.Second)
	must(t, err)
	defer overflow.Close()
	must(t, overflow.SetReadDeadline(time.Now().Add(time.Second)))
	var b [1]byte
	if _, err := overflow.Read(b[:]); err == nil {
		t.Fatal("overflow connection accepted")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("overflow connection queued")
	}
	if got := h.redemption.Stats(); got.Connections != 4 || got.Requests != 0 {
		t.Fatalf("overflow changed admission: %+v", got)
	}
}

func TestEnrollmentHTTPSeparatesProviderCapability(t *testing.T) {
	f := enrollmentSeed(t)
	root, key := testfixture.Root(t)
	cfg := EnrollmentHTTPConfig{Host: "localhost:443", ServerIdentity: testfixture.TLSIdentity(t, root, key, true), Trust: f.trust, Timeout: time.Second, MaxConnections: 2, MaxRequests: 1}
	if _, err := f.f.s.NewEnrollmentRedemptionServer(cfg); err == nil {
		t.Fatal("redemption lacks issuer provider")
	}
	cfg.Provider = f.provider(t)
	if _, err := f.f.s.NewEnrollmentActivationServer(cfg); err == nil {
		t.Fatal("activation received issuer provider capability")
	}
	adminConfig := f.config
	adminConfig.Profile = pki.Administrator
	adminTrust, err := pki.NewTrust(adminConfig)
	must(t, err)
	cfg.Trust = adminTrust
	if _, err := f.f.s.NewEnrollmentRedemptionServer(cfg); err == nil {
		t.Fatal("ordinary endpoint accepted administrator trust")
	}
}
