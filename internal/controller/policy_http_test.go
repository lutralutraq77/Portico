package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
	"portico.local/portico/internal/wire"
)

type policyHTTPFixture struct {
	client *http.Client
	host   string
	server *PolicyHTTPServer
}

func servePolicy(t *testing.T, p *PolicyEngine, c PolicyHTTPConfig, client tls.Certificate) *policyHTTPFixture {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	t.Cleanup(func() { _ = ln.Close() })
	if c.Host == "" {
		c.Host = "policy.portico.test"
	}
	root, rk := testfixture.Root(t)
	key := newKey(t)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{c.Host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, &key.PublicKey, rk)
	c.ServerIdentity = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	s, e := p.NewHTTPServer(c)
	must(t, e)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{client}}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != c.Host+":443" {
			return nil, ErrDenied
		}
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, s.Close(stop))
		if e := <-done; e != http.ErrServerClosed {
			t.Errorf("HTTP server shutdown: %v", e)
		}
	})
	return &policyHTTPFixture{client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, host: c.Host, server: s}
}

func (f *policyHTTPFixture) post(t *testing.T, path string, value any, result any) {
	t.Helper()
	b, e := json.Marshal(value)
	must(t, e)
	r, e := http.NewRequest(http.MethodPost, "https://"+f.host+path, bytes.NewReader(b))
	must(t, e)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+f.host)
	response, e := f.client.Do(r)
	must(t, e)
	defer func() { _ = response.Body.Close() }()
	data, e := io.ReadAll(io.LimitReader(response.Body, wire.MaxBody+1))
	must(t, e)
	if response.StatusCode != http.StatusOK || len(data) > wire.MaxBody {
		t.Fatalf("policy HTTP returned %d: %s", response.StatusCode, data)
	}
	if result != nil {
		must(t, json.Unmarshal(data, result))
	}
}

func TestPolicyHTTPRealTLSAndHostileRequests(t *testing.T) {
	v := newPolicyFixture(t)
	f := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Connector}, v.connectorIdentity)
	var permit Authorization
	f.post(t, "/api/v1/connector/authorize", v.request(), &permit)
	if permit.Resource.Address != v.device.f.resource.Address || permit.Resource.Port != 8096 {
		t.Fatal("wire permission widened endpoint")
	}
	var active Authorization
	f.post(t, "/api/v1/connector/activate", SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: 1}, &active)
	f.post(t, "/api/v1/connector/renew", SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: active.Sequence}, &active)
	f.post(t, "/api/v1/connector/close", SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: active.Sequence}, nil)
	valid, e := json.Marshal(v.request())
	must(t, e)
	for _, kind := range []string{"destination_override", "grant_override", "duplicate_field", "case_alias", "encoded_alias", "extra_json", "null", "oversized", "encoded_body", "wrong_type", "query", "host", "method", "unknown_route", "device_route", "admin_route"} {
		t.Run(kind, func(t *testing.T) {
			body := string(valid)
			path := "/api/v1/connector/authorize"
			method := http.MethodPost
			switch kind {
			case "destination_override":
				body = strings.TrimSuffix(body, "}") + `,"Address":"192.168.50.10","Port":22}`
			case "grant_override":
				body = strings.TrimSuffix(body, "}") + `,"GrantID":"` + v.device.f.grant.ID + `"}`
			case "duplicate_field":
				body = strings.TrimSuffix(body, "}") + `,"Version":1}`
			case "case_alias":
				body = strings.TrimSuffix(body, "}") + `,"version":1}`
			case "encoded_alias":
				body = strings.TrimSuffix(body, "}") + `,"\u0056ersion":1}`
			case "extra_json":
				body += `{}`
			case "null":
				body = "null"
			case "oversized":
				body = strings.Repeat(" ", wire.MaxBody) + body
			case "query":
				path += "?Port=22"
			case "method":
				method = http.MethodGet
			case "unknown_route":
				path = "/api/v1/connector/list"
			case "device_route":
				path = "/api/v1/device/catalog"
				body = "{}"
			case "admin_route":
				path = "/api/v1/admin/policy/preview"
				body = "{}"
			}
			r, e := http.NewRequest(method, "https://"+f.host+path, strings.NewReader(body))
			must(t, e)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Forwarded-User", v.device.f.user.ID)
			r.Header.Set("X-Admin", "true")
			if kind == "host" {
				r.Host = "evil.portico.test"
			}
			if kind == "wrong_type" {
				r.Header.Set("Content-Type", "text/plain")
			}
			if kind == "encoded_body" {
				r.Header.Set("Content-Encoding", "gzip")
			}
			before := summary(t, v.device.f.s)
			response, e := f.client.Do(r)
			must(t, e)
			data, e := io.ReadAll(response.Body)
			must(t, e)
			must(t, response.Body.Close())
			if response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("nonuniform rejection: %d %s", response.StatusCode, data)
			}
			if summary(t, v.device.f.s) != before {
				t.Fatal("hostile HTTP request committed state")
			}
		})
	}
}

func TestPolicyHTTPProfileIsolationAndLiveConnectionRevocation(t *testing.T) {
	v := newPolicyFixture(t)
	f := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Device}, v.deviceIdentity)
	var catalog control.CatalogSnapshot
	f.post(t, "/api/v1/device/catalog", struct{}{}, &catalog)
	if catalog.Version != 1 || len(catalog.Resources) != 1 {
		t.Fatal("incorrect private catalog")
	}
	must(t, v.device.f.s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.Disable("device", v.device.f.device.ID) }))
	r, e := http.NewRequest(http.MethodPost, "https://"+f.host+"/api/v1/device/catalog", strings.NewReader("{}"))
	must(t, e)
	r.Header.Set("Content-Type", "application/json")
	reused := false
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(c httptrace.GotConnInfo) { reused = c.Reused }}))
	response, e := f.client.Do(r)
	must(t, e)
	_, e = io.Copy(io.Discard, response.Body)
	must(t, e)
	must(t, response.Body.Close())
	if !reused || response.StatusCode != http.StatusForbidden {
		t.Fatal("revoked device retained authority over existing TLS connection")
	}
	for _, identity := range []tls.Certificate{{}, v.connectorIdentity} {
		server := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Device}, identity)
		r, e := http.NewRequest(http.MethodPost, "https://"+server.host+"/api/v1/device/catalog", strings.NewReader("{}"))
		must(t, e)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Client-Cert", base64.StdEncoding.EncodeToString(v.deviceLeaf))
		response, e := server.client.Do(r)
		if e == nil {
			_ = response.Body.Close()
			t.Fatal("wrong TLS profile entered device API")
		}
	}
}

func TestPolicyHTTPHardwareApprovalAndOrigin(t *testing.T) {
	a := adminSeed(t)
	p := policyFixtureFor(t, a.f).engine
	a.setupFactors(t)
	f := servePolicy(t, p, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	var preview PolicyPreview
	f.post(t, "/api/v1/admin/policy/preview", resourceDraft(a.f.f), &preview)
	var challenge AdminChallenge
	f.post(t, "/api/v1/admin/policy/challenge", previewApprovalRequest{preview.ID, preview.Digest}, &challenge)
	response := a.assertion(t, a.keys[0], challenge)
	f.post(t, "/api/v1/admin/policy/confirm", finishApprovalRequest{challenge.ID, response}, nil)
	for _, origin := range []string{"", "null", "https://attacker.test", "http://admin.portico.test"} {
		body, e := json.Marshal(resourceDraft(a.f.f))
		must(t, e)
		r, e := http.NewRequest(http.MethodPost, "https://"+f.host+"/api/v1/admin/policy/preview", bytes.NewReader(body))
		must(t, e)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		before := summary(t, a.f.f.s)
		response, e := f.client.Do(r)
		must(t, e)
		_, e = io.Copy(io.Discard, response.Body)
		must(t, e)
		must(t, response.Body.Close())
		if response.StatusCode != http.StatusForbidden || summary(t, a.f.f.s) != before {
			t.Fatal("cross-origin admin mutation accepted")
		}
	}
}
