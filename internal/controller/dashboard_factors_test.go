package controller

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

func factorRevision(t *testing.T, a *adminFixture) int64 {
	t.Helper()
	page, err := a.f.f.s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "security", Limit: 1})
	must(t, err)
	return page.PolicyRevision
}

func factorDenied(t *testing.T, f *policyHTTPFixture, path string, value any, change func(*http.Request)) {
	t.Helper()
	data, err := json.Marshal(value)
	must(t, err)
	request, err := http.NewRequest(http.MethodPost, "https://"+f.host+path, bytes.NewReader(data))
	must(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://"+f.host)
	if change != nil {
		change(request)
	}
	response, err := f.client.Do(request)
	must(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxBody+1))
	must(t, err)
	if response.StatusCode != http.StatusForbidden || string(body) != `{"error":"request rejected"}` {
		t.Fatalf("factor denial status=%d", response.StatusCode)
	}
}

func TestDashboardFactorHTTPBootstrapTestAndBackupRecovery(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	p := policyFixtureFor(t, a.f).engine
	f := servePolicy(t, p, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	begin := func(kind, target string) FactorChallenge {
		t.Helper()
		revision := factorRevision(t, a)
		var result FactorChallenge
		f.post(t, "/api/v1/admin/factors/challenge", FactorRequest{kind, target, revision}, &result)
		if result.Kind != kind || !validID(result.FactorID) || (target != "" && result.FactorID != target) || result.PolicyRevision != revision || !result.ExpiresAt.After(time.Now()) {
			t.Fatal("factor challenge changed operation, owner scope or expiry")
		}
		return result
	}
	for i, key := range a.keys[:2] {
		t.Run([]string{"primary_registration_and_test", "backup_registration_and_test"}[i], func(t *testing.T) {
			challenge := begin("bootstrap-factor", "")
			if challenge.Challenge.Registration == nil || challenge.Challenge.Approval != nil {
				t.Fatal("initial factor did not receive registration")
			}
			proof := key.Register(t, base64.RawURLEncoding.EncodeToString(challenge.Challenge.Registration.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
			var result FactorResult
			f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, &result)
			if result.Registration != nil {
				t.Fatal("registration repeated itself")
			}
			a.factors = append(a.factors, challenge.FactorID)
			var enabled, tested bool
			must(t, s.db.QueryRow("SELECT enabled,tested FROM admin_factors WHERE id=?", challenge.FactorID).Scan(&enabled, &tested))
			if !enabled || tested {
				t.Fatal("registration claimed that the new key was tested")
			}
			challenge = begin("test-factor", challenge.FactorID)
			allowed := challenge.Challenge.Approval.Response.AllowedCredentials
			if len(allowed) != 1 || !bytes.Equal(allowed[0].CredentialID, key.ID) {
				t.Fatal("test challenge did not select the exact key")
			}
			proof = a.assertion(t, key, challenge.Challenge)
			f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, &result)
			must(t, s.db.QueryRow("SELECT tested FROM admin_factors WHERE id=?", challenge.FactorID).Scan(&tested))
			if !tested {
				t.Fatal("actual key test did not persist")
			}
			before := summary(t, s)
			factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, nil)
			if summary(t, s) != before {
				t.Fatal("replay changed state")
			}
		})
	}
	t.Run("initial_window_cannot_add_a_third_key", func(t *testing.T) {
		factorDenied(t, f, "/api/v1/admin/factors/challenge", FactorRequest{"bootstrap-factor", "", factorRevision(t, a)}, nil)
	})
	t.Run("backup_retires_primary", func(t *testing.T) {
		challenge := begin("disable-factor", a.factors[0])
		allowed := challenge.Challenge.Approval.Response.AllowedCredentials
		if len(allowed) != 1 || !bytes.Equal(allowed[0].CredentialID, a.keys[1].ID) {
			t.Fatal("retirement offered the key being retired")
		}
		before := summary(t, s)
		factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, a.assertion(t, a.keys[0], challenge.Challenge)}, nil)
		if summary(t, s) != before {
			t.Fatal("self-retirement changed state")
		}
		f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, a.assertion(t, a.keys[1], challenge.Challenge)}, nil)
		var enabled bool
		must(t, s.db.QueryRow("SELECT enabled FROM admin_factors WHERE id=?", a.factors[0]).Scan(&enabled))
		if enabled {
			t.Fatal("backup approval did not retire the primary")
		}
		factorDenied(t, f, "/api/v1/admin/factors/challenge", FactorRequest{"test-factor", a.factors[0], factorRevision(t, a)}, nil)
		factorDenied(t, f, "/api/v1/admin/factors/challenge", FactorRequest{"disable-factor", a.factors[1], factorRevision(t, a)}, nil)
	})
	t.Run("backup_approves_replacement_then_new_key_is_tested", func(t *testing.T) {
		challenge := begin("register-factor", "")
		var result FactorResult
		f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, a.assertion(t, a.keys[1], challenge.Challenge)}, &result)
		if result.Registration == nil || result.Registration.Registration == nil || result.Registration.Approval != nil {
			t.Fatal("replacement did not require a separate registration")
		}
		key := a.keys[2]
		proof := key.Register(t, base64.RawURLEncoding.EncodeToString(result.Registration.Registration.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
		f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{result.Registration.ID, proof}, nil)
		challenge = begin("test-factor", challenge.FactorID)
		f.post(t, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, a.assertion(t, key, challenge.Challenge)}, nil)
		var enabled, tested int
		must(t, s.db.QueryRow("SELECT count(*),sum(tested) FROM admin_factors WHERE user_id=? AND enabled=1", a.f.f.user.ID).Scan(&enabled, &tested))
		if enabled != 2 || tested != 2 {
			t.Fatal("recovery did not restore two tested factor records")
		}
	})
}

func TestDashboardFactorInventoryOwnershipPaginationAndRedaction(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	other := NewID()
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{other, "Other owner", true}) }))
	_, err := s.db.Exec("INSERT INTO admin_factors VALUES(?,?,?,?,?,1,1)", NewID(), other, []byte("unrelated credential"), []byte("unrelated public key"), []byte("unrelated invalid credential body"))
	must(t, err)
	before := summary(t, s)
	request := DashboardRequest{Section: "factors", Limit: 1}
	ids := map[string]bool{}
	for range 2 {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, request)
		must(t, err)
		items := page.Items.([]DashboardFactor)
		if len(items) != 1 || !items[0].Enabled || !items[0].Tested || !validID(items[0].ModelID) || ids[items[0].ID] {
			t.Fatal("factor page repeated or exposed invalid metadata")
		}
		ids[items[0].ID] = true
		body, err := json.Marshal(page)
		must(t, err)
		for _, key := range a.keys[:2] {
			if bytes.Contains(body, []byte(base64.RawURLEncoding.EncodeToString(key.ID))) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(key.ID))) {
				t.Fatal("credential handle escaped metadata")
			}
		}
		request.After, request.PolicyRevision = page.Next, page.PolicyRevision
	}
	if len(ids) != 2 || !ids[a.factors[0]] || !ids[a.factors[1]] || request.After != "" || summary(t, s) != before {
		t.Fatal("factor inventory changed state or crossed owners")
	}
	request.After = a.factors[0]
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Changed policy", true}) }))
	if page, err := s.DashboardInventory(ctx, a.conn, a.trust, request); err == nil || page.Items != nil {
		t.Fatal("stale factor inventory survived")
	}
	_, err = s.db.Exec("UPDATE admin_factors SET credential_json=? WHERE id=?", []byte("invalid own factor metadata"), a.factors[0])
	must(t, err)
	if page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "factors", Limit: 50}); err == nil || page.Items != nil {
		t.Fatal("corrupt own metadata returned partial results")
	}
}

func TestDashboardFactorHTTPRejectsConfusedOperationsAndStaleAuthority(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	p := policyFixtureFor(t, a.f).engine
	f := servePolicy(t, p, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	for _, kind := range []string{"invite", "apply-policy"} {
		t.Run(kind, func(t *testing.T) {
			var challenge AdminChallenge
			if kind == "invite" {
				challenge = a.begin(t, a.invitation())
			} else {
				challenge = beginPolicy(t, a, p, previewPolicy(t, a, p, resourceDraft(a.f.f)))
			}
			before := summary(t, s)
			factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.ID, a.assertion(t, a.keys[0], challenge)}, nil)
			if summary(t, s) != before {
				t.Fatal("factor completion consumed a different operation")
			}
		})
	}
	revision := factorRevision(t, a)
	for _, request := range []FactorRequest{{"invite", NewID(), revision}, {"test-factor", NewID(), revision}, {"bootstrap-factor", NewID(), revision}, {"register-factor", NewID(), revision}, {"test-factor", a.factors[0], 0}, {"test-factor", a.factors[0], revision - 1}} {
		before := summary(t, s)
		factorDenied(t, f, "/api/v1/admin/factors/challenge", request, nil)
		if summary(t, s) != before {
			t.Fatal("invalid factor draft changed state")
		}
	}
	for _, path := range []string{"/api/v1/admin/factors/challenge", "/api/v1/admin/factors/confirm"} {
		for _, origin := range []string{"", "null", "https://other.portico.test"} {
			before := summary(t, s)
			factorDenied(t, f, path, FactorRequest{"test-factor", a.factors[0], revision}, func(r *http.Request) { r.Header.Set("Origin", origin) })
			if summary(t, s) != before {
				t.Fatal("cross-origin factor request changed state")
			}
		}
	}
	var challenge FactorChallenge
	f.post(t, "/api/v1/admin/factors/challenge", FactorRequest{"test-factor", a.factors[0], revision}, &challenge)
	proof := a.assertion(t, a.keys[0], challenge.Challenge)
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Concurrent change", true}) }))
	before := summary(t, s)
	factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, nil)
	if summary(t, s) != before {
		t.Fatal("stale factor confirmation changed state")
	}
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
	before = summary(t, s)
	factorDenied(t, f, "/api/v1/admin/factors/challenge", FactorRequest{"test-factor", a.factors[0], revision}, nil)
	factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, nil)
	if summary(t, s) != before {
		t.Fatal("revoked administrator retained factor authority")
	}
}

func TestDashboardFactorApprovalRequiresPreviouslyTestedKey(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	for i, key := range a.keys[:2] {
		challenge, err := s.BeginInitialFactor(ctx, a.conn, a.trust, a.verifier)
		must(t, err)
		id := a.register(t, key, challenge)
		a.factors = append(a.factors, id)
		if i == 0 {
			a.verifyKey(t, key, id)
		}
	}
	// The only tested key cannot be retired using the as-yet untested backup.
	before := summary(t, s)
	if _, err := s.BeginFactor(ctx, a.conn, a.trust, a.verifier, FactorRequest{"disable-factor", a.factors[0], factorRevision(t, a)}); err == nil {
		t.Error("untested backup was offered as authority to retire the tested key")
	}
	if summary(t, s) != before {
		t.Error("denied retirement staged a ceremony")
	}
	challenge, err := s.BeginFactor(ctx, a.conn, a.trust, a.verifier, FactorRequest{"register-factor", "", factorRevision(t, a)})
	must(t, err)
	allowed := challenge.Challenge.Approval.Response.AllowedCredentials
	if len(allowed) != 1 || !bytes.Equal(allowed[0].CredentialID, a.keys[0].ID) {
		t.Error("untested credential offered for administrative approval")
	}
	before = summary(t, s)
	if _, err := s.FinishFactor(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, a.assertion(t, a.keys[1], challenge.Challenge)); err == nil {
		t.Error("untested credential authorized registration")
	}
	if summary(t, s) != before {
		t.Error("rejected untested-key proof changed state")
	}
	// Defense in depth: a credential losing its tested state after challenge
	// creation is rejected at completion, even if the policy revision is unchanged.
	_, err = s.db.Exec("UPDATE admin_factors SET tested=0 WHERE id=?", a.factors[0])
	must(t, err)
	before = summary(t, s)
	if _, err := s.FinishFactor(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, a.assertion(t, a.keys[0], challenge.Challenge)); err == nil {
		t.Error("completion ignored current tested state")
	}
	if summary(t, s) != before {
		t.Error("stale tested-key proof changed state")
	}
	a.verifyKey(t, a.keys[1], a.factors[1])
	challenge, err = s.BeginFactor(ctx, a.conn, a.trust, a.verifier, FactorRequest{"disable-factor", a.factors[0], factorRevision(t, a)})
	must(t, err)
	_, err = s.FinishFactor(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, a.assertion(t, a.keys[1], challenge.Challenge))
	must(t, err)
}
