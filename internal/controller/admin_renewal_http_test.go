package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type renewalHTTPFixture struct {
	server  *AdminRenewalActivationServer
	address string
	host    string
	roots   *x509.CertPool
}

func serveRenewalActivation(t *testing.T, a *adminFixture) *renewalHTTPFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	root, rootKey := testfixture.Root(t)
	key := newKey(t)
	host := "admin.portico.test"
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, key.Public(), rootKey)
	s, err := a.f.f.s.NewAdminRenewalActivationServer(AdminRenewalActivationConfig{Host: host, ServerIdentity: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}, Trust: a.trust, Timeout: time.Second, MaxConnections: 2, MaxRequests: 1})
	must(t, err)
	done := make(chan error, 1)
	go func() { done <- s.Serve(listener) }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, s.Close(stop))
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("renewal activation shutdown: %v", err)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &renewalHTTPFixture{server: s, address: listener.Addr().String(), host: host, roots: roots}
}

func (f *renewalHTTPFixture) client(t *testing.T, identity tls.Certificate) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.roots, Certificates: []tls.Certificate{identity}}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != f.host+":443" {
			return nil, ErrDenied
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (f *renewalHTTPFixture) request(t *testing.T, client *http.Client, body []byte, change func(*http.Request)) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://"+f.host+adminrenewal.ActivatePath, bytes.NewReader(body))
	must(t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+f.host)
	if change != nil {
		change(r)
	}
	response, err := client.Do(r)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, adminrenewal.MaxActivationBody+1))
	must(t, err)
	if len(data) > adminrenewal.MaxActivationBody || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Frame-Options") != "DENY" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("unbounded or unprotected activation response")
	}
	return response.StatusCode, data
}

func TestAdministratorRenewalHTTPRejectsHostileInputBeforeAtomicActivation(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	id := a.approveRenewal(t)
	identity := a.issueRenewal(t, id)
	f := serveRenewalActivation(t, a)
	client := f.client(t, identity)
	valid, err := json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: id})
	must(t, err)
	before := summary(t, s)
	for _, scenario := range []string{"unknown", "duplicate", "case", "encoded-name", "trailing", "null", "oversized", "wrong-id", "version", "method", "host", "origin", "cookie", "authorization", "encoding", "content-type", "query", "empty-query", "encoded-path", "dashboard", "issuer", "ordinary"} {
		t.Run(scenario, func(t *testing.T) {
			body := bytes.Clone(valid)
			change := func(r *http.Request) {
				switch scenario {
				case "method":
					r.Method = http.MethodGet
				case "host":
					r.Host = "other.portico.test"
				case "origin":
					r.Header.Del("Origin")
				case "cookie":
					r.Header.Set("Cookie", "session=fixture")
				case "authorization":
					r.Header.Set("Authorization", "Bearer fixture")
				case "encoding":
					r.Header.Set("Content-Encoding", "gzip")
				case "content-type":
					r.Header.Set("Content-Type", "text/plain")
				case "query":
					r.URL.RawQuery = "approve=true"
				case "empty-query":
					r.URL.ForceQuery = true
				case "encoded-path":
					r.URL.RawPath = "/api/v1/admin/renewal/%61ctivate"
				case "dashboard":
					r.URL.Path = "/api/v1/admin/dashboard/inventory"
				case "issuer":
					r.URL.Path = "/1.0/sign"
				case "ordinary":
					r.URL.Path = "/api/v1/enrollment/activate"
				}
			}
			switch scenario {
			case "unknown":
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"Approved":true}`)
			case "duplicate":
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"Version":1}`)
			case "case":
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"version":1}`)
			case "encoded-name":
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"\u0056ersion":1}`)
			case "trailing":
				body = append(body, []byte("{}")...)
			case "null":
				body = []byte("null")
			case "oversized":
				body = append(bytes.Repeat([]byte(" "), adminrenewal.MaxActivationBody), body...)
			case "wrong-id":
				body, err = json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: NewID()})
				must(t, err)
			case "version":
				body, err = json.Marshal(adminrenewal.ActivateRequest{Version: 2, RenewalID: id})
				must(t, err)
			}
			status, data := f.request(t, client, body, change)
			if status != http.StatusForbidden || string(data) != `{"error":"request rejected"}` || summary(t, s) != before {
				t.Fatal("hostile request reached activation or changed response scope")
			}
		})
	}
	forged := httptest.NewRequest(http.MethodPost, "https://"+f.host+adminrenewal.ActivatePath, bytes.NewReader(valid))
	forged.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{parseCert(t, identity.Certificate[0])}}
	forged.Header.Set("Content-Type", "application/json")
	forged.Header.Set("Origin", "https://"+f.host)
	recorder := httptest.NewRecorder()
	f.server.server.Handler.ServeHTTP(recorder, forged)
	if recorder.Code != http.StatusForbidden || summary(t, s) != before {
		t.Fatal("caller-supplied TLS metadata bypassed actual connection ownership")
	}
	status, data := f.request(t, client, valid, nil)
	if status != http.StatusOK {
		t.Fatal("approved TLS candidate did not activate")
	}
	var result adminrenewal.Activated
	must(t, json.Unmarshal(data, &result))
	if result.Version != 1 || result.RenewalID != id || result.CertificateSHA256 != pki.Hash(identity.Certificate[0]) {
		t.Fatal("activation confirmation lost the certificate binding")
	}
	after := summary(t, s)
	status, _ = f.request(t, client, valid, nil)
	if status != http.StatusOK || summary(t, s) != after {
		t.Fatal("confirmation retry changed authority or audit")
	}
	if _, err = tlsHandshake(t, s, a.trust, a.identity, false); err == nil {
		t.Fatal("old administrator leaf survived HTTP activation")
	}
	_, err = tlsHandshake(t, s, a.trust, identity, false)
	must(t, err)
	must(t, verifyAudit(ctx, s.db))
}

func TestAdministratorRenewalHTTPRejectsWrongTLSAndChangedAuthority(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	ordinary := a.f.issue(t)
	id := a.approveRenewal(t)
	identity := a.issueRenewal(t, id)
	f := serveRenewalActivation(t, a)
	body, err := json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: id})
	must(t, err)
	wrongKey := identity
	wrongKey.PrivateKey = newKey(t)
	for _, certificate := range []tls.Certificate{a.identity, wrongKey, tlsIdentity(ordinary.invited), {}} {
		status, _ := f.request(t, f.client(t, certificate), body, nil)
		if status != 0 {
			t.Fatal("unapproved TLS identity reached the activation handler")
		}
	}
	must(t, s.Update(ctx, a.userID, func(tx *Tx) error { return tx.Disable("device", a.deviceID) }))
	status, _ := f.request(t, f.client(t, identity), body, nil)
	if status != 0 {
		t.Fatal("candidate bypassed a changed policy revision")
	}
	if err = s.Update(ctx, a.userID, func(tx *Tx) error { return tx.RevokeAdminRenewal(id) }); err != nil {
		t.Fatal(err)
	}
}

func TestAdministratorRenewalHTTPBoundsUnauthenticatedConnections(t *testing.T) {
	a := adminSeed(t)
	f := serveRenewalActivation(t, a)
	var held []net.Conn
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	for range 2 {
		conn, err := net.DialTimeout("tcp", f.address, time.Second)
		must(t, err)
		held = append(held, conn)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for f.server.connections.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.server.connections.Load() != 2 {
		t.Fatal("fixture connections were not admitted")
	}
	extra, err := net.DialTimeout("tcp", f.address, time.Second)
	must(t, err)
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var one [1]byte
	_, err = extra.Read(one[:])
	if err != io.EOF || f.server.connections.Load() != 2 || len(f.server.requests) != 0 {
		t.Fatal("excess unauthenticated connection was retained")
	}
}

func TestAdministratorRenewalHTTPRejectsExcessBodiesWithoutQueue(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	id := a.approveRenewal(t)
	identity := a.issueRenewal(t, id)
	f := serveRenewalActivation(t, a)
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.roots, ServerName: f.host, Certificates: []tls.Certificate{identity}})
	must(t, err)
	defer connection.Close()
	must(t, connection.SetDeadline(time.Now().Add(3*time.Second)))
	body, err := json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: id})
	must(t, err)
	// Send a real authenticated request header and hold its body incomplete.
	_, err = fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://%s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", adminrenewal.ActivatePath, f.host, f.host, len(body))
	must(t, err)
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(f.server.requests) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(f.server.requests) != 1 {
		t.Fatal("authenticated body fixture did not enter the request bound")
	}
	before := summary(t, s)
	status, _ := f.request(t, f.client(t, identity), body, nil)
	if status != http.StatusForbidden || len(f.server.requests) != 1 || summary(t, s) != before {
		t.Fatal("excess body was queued or changed administrator authority")
	}
	must(t, connection.Close())
	stop, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	must(t, f.server.Close(stop))
	if len(f.server.requests) != 0 || f.server.connections.Load() != 0 || summary(t, s) != before {
		t.Fatal("activation server shutdown retained requests or connections")
	}
}

func TestAdministratorRenewalHTTPRejectsInvalidConfigurationAndPublicListener(t *testing.T) {
	a := adminSeed(t)
	root, key := testfixture.Root(t)
	base := AdminRenewalActivationConfig{Host: "admin.portico.test", ServerIdentity: testfixture.TLSIdentity(t, root, key, true), Trust: a.trust, Timeout: time.Second, MaxConnections: 2, MaxRequests: 1}
	for _, scenario := range []string{"trust", "ordinary", "host", "path", "timeout", "connections", "requests", "more-requests", "identity"} {
		t.Run(scenario, func(t *testing.T) {
			c := base
			switch scenario {
			case "trust":
				c.Trust = nil
			case "ordinary":
				c.Trust = a.f.trust
			case "host":
				c.Host = "Admin.portico.test"
			case "path":
				c.Host += "/admin"
			case "timeout":
				c.Timeout = 6 * time.Second
			case "connections":
				c.MaxConnections = 9
			case "requests":
				c.MaxRequests = 0
			case "more-requests":
				c.MaxRequests = 3
			case "identity":
				c.ServerIdentity = tls.Certificate{}
			}
			if server, err := a.f.f.s.NewAdminRenewalActivationServer(c); err == nil {
				_ = server.Close(ctx)
				t.Fatal("invalid activation configuration accepted")
			}
		})
	}
	server, err := a.f.f.s.NewAdminRenewalActivationServer(base)
	must(t, err)
	defer server.Close(ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer listener.Close()
	if err = server.Serve(&renewalOutsideListener{Listener: listener}); err != ErrDenied {
		t.Fatal("activation listener accepted a non-loopback address")
	}
}

type renewalOutsideListener struct{ net.Listener }

func (l *renewalOutsideListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}
