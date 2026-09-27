package controller

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"

	"portico.local/portico/internal/pki"
)

func dashboardGET(t *testing.T, f *policyHTTPFixture, path string, change func(*http.Request)) (*http.Response, []byte, bool) {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://"+f.host+path, nil)
	must(t, err)
	if change != nil {
		change(r)
	}
	reused := false
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
	response, err := f.client.Do(r)
	must(t, err)
	data, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	must(t, err)
	must(t, response.Body.Close())
	return response, data, reused
}

func TestDashboardAssetsAuthenticatedAndNonMutating(t *testing.T) {
	a := adminSeed(t)
	f := servePolicy(t, policyFixtureFor(t, a.f).engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	before := summary(t, a.f.f.s)
	for _, asset := range []struct{ path, contentType string }{{"/admin", "text/html; charset=utf-8"}, {"/admin.css", "text/css; charset=utf-8"}, {"/admin.js", "text/javascript; charset=utf-8"}} {
		t.Run(asset.path, func(t *testing.T) {
			for _, site := range []string{"", "none", "same-origin"} {
				response, data, _ := dashboardGET(t, f, asset.path, func(r *http.Request) {
					if site != "" {
						r.Header.Set("Sec-Fetch-Site", site)
					}
					if site == "same-origin" {
						r.Header.Set("Origin", "https://"+f.host)
					}
				})
				if response.StatusCode != http.StatusOK || len(data) == 0 || response.Header.Get("Content-Type") != asset.contentType || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Security-Policy") != dashboardCSP || response.Header.Get("Referrer-Policy") != "no-referrer" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("X-Frame-Options") != "DENY" {
					t.Fatal("asset did not preserve private delivery headers")
				}
				if strings.Contains(string(data), a.f.f.user.ID) || strings.Contains(string(data), a.f.f.device.ID) {
					t.Fatal("asset contains embedded deployment data")
				}
			}
		})
	}
	if summary(t, a.f.f.s) != before {
		t.Fatal("asset reads changed policy or audit state")
	}
}

func TestDashboardAssetsRejectHostileRequestsAndLiveRevocation(t *testing.T) {
	a := adminSeed(t)
	f := servePolicy(t, policyFixtureFor(t, a.f).engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	for _, change := range []struct {
		name, path string
		apply      func(*http.Request)
	}{
		{"unknown", "/admin/unknown", nil}, {"query", "/admin?secret=fixture", nil}, {"empty_query", "/admin?", nil},
		{"encoded_path", "/%61dmin", nil}, {"traversal", "/admin/../admin.js", nil}, {"encoded_slash", "/admin%2f..%2fadmin.js", nil},
		{"host", "/admin", func(r *http.Request) { r.Host = "attacker.test" }},
		{"origin", "/admin", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.test") }},
		{"duplicate_origin", "/admin", func(r *http.Request) {
			r.Header.Add("Origin", "https://"+f.host)
			r.Header.Add("Origin", "https://attacker.test")
		}},
		{"empty_origin", "/admin", func(r *http.Request) { r.Header.Set("Origin", "") }},
		{"same_site", "/admin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		{"cross_site", "/admin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"encoding", "/admin", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"body", "/admin", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{}")); r.ContentLength = 2 }},
		{"type", "/admin", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{"range", "/admin", func(r *http.Request) { r.Header.Set("Range", "bytes=0-1") }},
		{"post", "/admin", func(r *http.Request) { r.Method = http.MethodPost; r.Header.Set("Content-Type", "application/json") }},
		{"head", "/admin", func(r *http.Request) { r.Method = http.MethodHead }},
	} {
		t.Run(change.name, func(t *testing.T) {
			response, data, _ := dashboardGET(t, f, change.path, change.apply)
			if response.StatusCode != http.StatusForbidden || (change.name != "head" && string(data) != `{"error":"request rejected"}`) {
				t.Fatalf("asset request was not uniformly rejected: %d", response.StatusCode)
			}
		})
	}
	response, _, _ := dashboardGET(t, f, "/admin", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("positive control failed")
	}
	must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
	for _, path := range []string{"/admin", "/admin.css", "/admin.js"} {
		response, data, reused := dashboardGET(t, f, path, func(r *http.Request) {
			r.Header.Set("Cookie", "admin=true")
			r.Header.Set("X-Forwarded-Client-Cert", "administrator")
		})
		if !reused || response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` {
			t.Fatal("revoked administrator retained assets over reused connection")
		}
	}
}

func TestDashboardAssetsProfileIsolationAndEmergency(t *testing.T) {
	v := newPolicyFixture(t)
	for _, identity := range []struct {
		profile pki.Profile
		cert    tls.Certificate
	}{{pki.Device, v.deviceIdentity}, {pki.Connector, v.connectorIdentity}} {
		f := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: identity.profile}, identity.cert)
		for _, path := range []string{"/admin", "/admin.css", "/admin.js"} {
			response, _, _ := dashboardGET(t, f, path, nil)
			if response.StatusCode != http.StatusForbidden {
				t.Fatal("ordinary profile entered administrator assets")
			}
		}
	}
	a := adminSeed(t)
	f := servePolicy(t, policyFixtureFor(t, a.f).engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	response, _, _ := dashboardGET(t, f, "/admin", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("positive control failed")
	}
	a.f.f.s.EmergencyDeny()
	response, _, reused := dashboardGET(t, f, "/admin", nil)
	if !reused || response.StatusCode != http.StatusForbidden {
		t.Fatal("emergency stop allowed asset read")
	}
}
