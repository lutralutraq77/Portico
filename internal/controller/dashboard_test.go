package controller

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"reflect"
	"sort"
	"strings"
	"testing"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

func TestDashboardInventoryPagesAndCurrentResource(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	ids := []string{a.f.f.user.ID}
	for range 4 {
		id := NewID()
		ids = append(ids, id)
		must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{id, "Fixture user", true}) }))
	}
	sort.Strings(ids)
	before := summary(t, s)
	request := DashboardRequest{Section: "users", Limit: 2}
	var got []string
	for range 3 {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, request)
		must(t, err)
		items := page.Items.([]DashboardUser)
		if page.Version != 1 || len(items) > 2 || page.ObservedAt.IsZero() {
			t.Fatal("invalid bounded page")
		}
		for _, item := range items {
			got = append(got, item.ID)
		}
		request.After, request.PolicyRevision = page.Next, page.PolicyRevision
	}
	if !reflect.DeepEqual(ids, got) || request.After != "" || before != summary(t, s) {
		t.Fatal("pagination omitted, repeated, or mutated inventory")
	}
	resource := a.f.f.resource
	resource.Revision++
	resource.Port = 8443
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.ReviseResource(1, resource) }))
	if page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "users", Limit: 2, After: ids[1], PolicyRevision: request.PolicyRevision}); err == nil || page.Items != nil {
		t.Fatal("stale page returned data")
	}
	page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "resources", Limit: 50})
	must(t, err)
	resources := page.Items.([]DashboardResource)
	if len(resources) != 1 || resources[0].Revision != 2 || resources[0].Port != 8443 {
		t.Fatal("inventory exposed obsolete resource revision")
	}
	for _, section := range []string{"devices", "connectors", "certificates"} {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: section, Limit: 50})
		must(t, err)
		if reflect.ValueOf(page.Items).Len() == 0 {
			t.Fatalf("missing %s metadata", section)
		}
	}
}

func TestDashboardInventoryRedactsBeforeSerialization(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	op := a.invitation()
	challenge := a.begin(t, op)
	result, err := a.f.f.s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, a.assertion(t, a.keys[0], challenge))
	must(t, err)
	if result.InvitationSecret == "" {
		t.Fatal("fixture has no secret to protect")
	}
	var tokenHash string
	must(t, a.f.f.s.db.QueryRow("SELECT token_hash FROM enrollments WHERE id=?", op.TargetID).Scan(&tokenHash))
	server := servePolicy(t, policyFixtureFor(t, a.f).engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	before := summary(t, a.f.f.s)
	for _, section := range []string{"users", "devices", "connectors", "resources", "enrollments", "certificates"} {
		var raw json.RawMessage
		server.post(t, "/api/v1/admin/dashboard/inventory", DashboardRequest{Section: section, Limit: 50}, &raw)
		for _, forbidden := range []string{result.InvitationSecret, tokenHash, "InvitationSecret", "token_hash", "TokenHash", "CSR", "PrivateKey", "credential_json", "operation_json", "CertificateDER"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("%s leaked protected field or value", section)
			}
		}
		var response struct{ Items []map[string]json.RawMessage }
		must(t, json.Unmarshal(raw, &response))
		if section == "enrollments" {
			allowed := map[string]bool{"ID": true, "IssuerID": true, "PrincipalID": true, "Profile": true, "State": true, "ExpiresAt": true, "NotAfter": true}
			found := false
			for _, item := range response.Items {
				var id string
				must(t, json.Unmarshal(item["ID"], &id))
				found = found || id == op.TargetID
				for field := range item {
					if !allowed[field] {
						t.Fatalf("unreviewed enrollment field %s", field)
					}
				}
			}
			if !found {
				t.Fatal("missing enrollment status")
			}
		}
	}
	if summary(t, a.f.f.s) != before {
		t.Fatal("inventory changed security state")
	}
}

func dashboardHTTP(t *testing.T, f *policyHTTPFixture, body, origin string) (*http.Response, []byte, bool) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://"+f.host+"/api/v1/admin/dashboard/inventory", strings.NewReader(body))
	must(t, err)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-Admin", "true")
	r.Header.Set("X-Forwarded-Client-Cert", "untrusted administrator claim")
	reused := false
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
	response, err := f.client.Do(r)
	must(t, err)
	data, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxBody+1))
	must(t, err)
	must(t, response.Body.Close())
	return response, data, reused
}

func TestDashboardInventoryRejectsHostileRequestsAndLiveRevocation(t *testing.T) {
	a := adminSeed(t)
	p := policyFixtureFor(t, a.f).engine
	f := servePolicy(t, p, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	valid := `{"Section":"users","Limit":2}`
	response, _, _ := dashboardHTTP(t, f, valid, "https://"+f.host)
	if response.StatusCode != http.StatusOK {
		t.Fatal("authenticated metadata unavailable")
	}
	before := summary(t, a.f.f.s)
	for _, body := range []string{
		`{"Section":"users","Limit":0}`, `{"Section":"users","Limit":51}`, `{"Section":"users","Limit":-1}`,
		`{"Section":"admin_factors","Limit":2}`, `{"Section":"users; DROP TABLE users","Limit":2}`,
		`{"Section":"users","Limit":2,"IncludeSecrets":true}`, `{"Section":"users","Limit":2,"section":"enrollments"}`,
		`{"Section":"users","Limit":2,"After":"' OR 1=1 --","PolicyRevision":1}`,
		`{"Section":"users","Limit":2,"After":"` + NewID() + `"}`, `{"Section":"users","Limit":2,"PolicyRevision":-1}`,
		`null`, valid + `{}`,
	} {
		response, data, _ := dashboardHTTP(t, f, body, "https://"+f.host)
		if response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("hostile request disclosed data")
		}
	}
	for _, origin := range []string{"", "null", "https://attacker.test", "http://admin.portico.test"} {
		response, _, _ := dashboardHTTP(t, f, valid, origin)
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("cross-origin inventory disclosed")
		}
	}
	if summary(t, a.f.f.s) != before {
		t.Fatal("rejection mutated inventory")
	}
	must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
	response, data, reused := dashboardHTTP(t, f, valid, "https://"+f.host)
	if !reused || response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` {
		t.Fatal("revoked administrator retained inventory over reused TLS connection")
	}
}

func TestDashboardInventoryProfileIsolationAndEmergency(t *testing.T) {
	v := newPolicyFixture(t)
	for _, identity := range []struct {
		profile pki.Profile
		cert    tls.Certificate
	}{{pki.Device, v.deviceIdentity}, {pki.Connector, v.connectorIdentity}} {
		f := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: identity.profile}, identity.cert)
		response, _, _ := dashboardHTTP(t, f, `{"Section":"users","Limit":2}`, "https://"+f.host)
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("ordinary profile entered administrator inventory")
		}
	}
	a := adminSeed(t)
	if _, err := a.f.f.s.DashboardInventory(ctx, nil, a.trust, DashboardRequest{Section: "users", Limit: 2}); err == nil {
		t.Fatal("missing TLS proof accepted")
	}
	a.f.f.s.EmergencyDeny()
	if page, err := a.f.f.s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "users", Limit: 2}); err == nil || page.Items != nil {
		t.Fatal("emergency stop exposed metadata")
	}
}
