package controller

import (
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func lifecycleDraft(t *testing.T, a *adminFixture, draft LifecycleDraft) PolicyDraft {
	t.Helper()
	draft.PolicyRevision = factorRevision(t, a)
	return PolicyDraft{Lifecycle: &draft}
}

func lifecycleAdminSeed(t *testing.T) *adminFixture {
	t.Helper()
	f := enrollmentSeed(t)
	user, device := NewID(), NewID()
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error {
		if err := tx.AddUser(User{ID: user, Name: "Independent administrator", Enabled: true}); err != nil {
			return err
		}
		return tx.AddDevice(Device{ID: device, UserID: user, Name: "Administrator machine", Platform: "linux", Enabled: true, NotAfter: tx.now.Add(2 * time.Hour)})
	}))
	return adminSeedFor(t, f, user, device)
}

func TestPolicyLifecycleHTTPCreateRenameAndNoImplicitCredentials(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p, s := policyFixtureFor(t, a.f).engine, a.f.f.s
	f := servePolicy(t, p, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	apply := func(draft LifecycleDraft) PolicyPreview {
		t.Helper()
		request := lifecycleDraft(t, a, draft)
		var view PolicyPreview
		f.post(t, "/api/v1/admin/policy/preview", request, &view)
		if view.Kind != draft.Kind || view.PolicyRevision != request.Lifecycle.PolicyRevision || view.Lifecycle == nil || !validID(view.Lifecycle.ID) || view.Lifecycle.Name != draft.Name || view.Resource.ID != "" || view.Previous != nil {
			t.Fatal("lifecycle preview changed the draft or included resource authority")
		}
		request.Lifecycle.Name = "mutated after preview"
		var challenge AdminChallenge
		f.post(t, "/api/v1/admin/policy/challenge", previewApprovalRequest{ID: view.ID, Digest: view.Digest}, &challenge)
		proof := a.assertion(t, a.keys[0], challenge)
		f.post(t, "/api/v1/admin/policy/confirm", finishApprovalRequest{challenge.ID, proof}, nil)
		before := summary(t, s)
		factorDenied(t, f, "/api/v1/admin/policy/confirm", finishApprovalRequest{challenge.ID, proof}, nil)
		if summary(t, s) != before {
			t.Fatal("replay changed state")
		}
		return view
	}
	user := apply(LifecycleDraft{Kind: "create-user", Name: "New operator"})
	device := apply(LifecycleDraft{Kind: "create-device", Name: "New laptop", UserID: user.Lifecycle.ID, Platform: "linux", NotAfter: s.now().Add(time.Hour)})
	connector := apply(LifecycleDraft{Kind: "create-connector", Name: "New connector"})
	if device.Lifecycle.UserName != user.Lifecycle.Name || device.Lifecycle.UserID != user.Lifecycle.ID || device.Lifecycle.Platform != "linux" || connector.Lifecycle.Version != "unreported" {
		t.Fatal("preview omitted actual owner, platform or unreported version")
	}
	for _, view := range []PolicyPreview{user, device, connector} {
		entity := strings.TrimPrefix(view.Kind, "create-")
		name := "Renamed " + entity
		renamed := apply(LifecycleDraft{Kind: "rename-" + entity, TargetID: view.Lifecycle.ID, Name: name})
		if renamed.PreviousName != view.Lifecycle.Name || renamed.Lifecycle.ID != view.Lifecycle.ID {
			t.Fatal("rename omitted old name or changed identity")
		}
		var stored string
		table := map[string]string{"user": "users", "device": "devices", "connector": "connectors"}[entity]
		must(t, s.db.QueryRow("SELECT name FROM "+table+" WHERE id=?", view.Lifecycle.ID).Scan(&stored))
		if stored != name {
			t.Fatal("rename did not commit its reviewed name")
		}
	}
	for query, id := range map[string]string{
		"SELECT count(*) FROM enrollments WHERE device_id=?":      device.Lifecycle.ID,
		"SELECT count(*) FROM certificates WHERE connector_id=?":  connector.Lifecycle.ID,
		"SELECT count(*) FROM grants WHERE user_id=?":             user.Lifecycle.ID,
		"SELECT count(*) FROM host_bindings WHERE connector_id=?": connector.Lifecycle.ID,
	} {
		var count int
		must(t, s.db.QueryRow(query, id).Scan(&count))
		if count != 0 {
			t.Fatal("metadata creation issued a credential or created access")
		}
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestPolicyLifecycleRevocationCancelsDependentAuthority(t *testing.T) {
	for _, entity := range []string{"user", "device", "connector"} {
		t.Run(entity, func(t *testing.T) {
			f := enrollmentSeed(t)
			adminUser, adminDevice := NewID(), NewID()
			must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error {
				if err := tx.AddUser(User{ID: adminUser, Name: "Independent administrator", Enabled: true}); err != nil {
					return err
				}
				return tx.AddDevice(Device{ID: adminDevice, UserID: adminUser, Name: "Administrator machine", Platform: "linux", Enabled: true, NotAfter: tx.now.Add(2 * time.Hour)})
			}))
			a := adminSeedFor(t, f, adminUser, adminDevice)
			a.setupFactors(t)
			v := policyFixtureFor(t, f)
			p, s := v.engine, f.f.s
			permit, err := p.Authorize(ctx, v.connectorConn, v.request())
			must(t, err)
			active, err := p.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: permit.Sequence})
			must(t, err)
			id := map[string]string{"user": f.f.user.ID, "device": f.f.device.ID, "connector": f.f.connector.ID}[entity]
			view := applyPolicy(t, a, p, lifecycleDraft(t, a, LifecycleDraft{Kind: "disable-" + entity, TargetID: id}))
			if view.Lifecycle == nil || view.Lifecycle.ID != id || view.Lifecycle.Entity != entity {
				t.Fatal("revocation preview changed target")
			}
			if _, err := p.Renew(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: active.Sequence}); err == nil {
				t.Fatal("revoked authority renewed an existing session")
			}
			if _, err := p.Authorize(ctx, v.connectorConn, v.request()); err == nil {
				t.Fatal("revoked authority opened a new session")
			}
			var state, reason string
			must(t, s.db.QueryRow("SELECT state FROM authorized_sessions WHERE id=?", permit.SessionID).Scan(&state))
			must(t, s.db.QueryRow("SELECT reason FROM session_cancellations WHERE session_id=?", permit.SessionID).Scan(&reason))
			if state != "closed" || reason != "closed" {
				t.Fatal("revocation did not enqueue dependent session cancellation")
			}
			if _, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "security", Limit: 1}); err != nil {
				t.Fatal("revocation removed unrelated administrator authority")
			}
			if _, err := p.Preview(ctx, a.conn, a.trust, lifecycleDraft(t, a, LifecycleDraft{Kind: "disable-" + entity, TargetID: id})); err == nil {
				t.Fatal("tombstone accepted a second revocation")
			}
			must(t, verifyAudit(ctx, s.db))
		})
	}
}

func TestPolicyLifecycleRejectsMalformedStaleAndLockoutDrafts(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p, s := policyFixtureFor(t, a.f).engine, a.f.f.s
	for _, draft := range []LifecycleDraft{
		{Kind: "enable-user", TargetID: a.f.f.user.ID},
		{Kind: "create-admin", Name: "not a public operation"},
		{Kind: "create-user", Name: ""},
		{Kind: "create-user", Name: "unsafe\nname"},
		{Kind: "create-user", Name: "Chosen ID", TargetID: NewID()},
		{Kind: "create-user", Name: "Extra owner", UserID: a.f.f.user.ID},
		{Kind: "create-connector", Name: "Extra platform", Platform: "linux"},
		{Kind: "create-device", Name: "Wrong owner", UserID: NewID(), Platform: "linux", NotAfter: s.now().Add(time.Hour)},
		{Kind: "create-device", Name: "Wrong platform", UserID: a.f.f.user.ID, Platform: "router", NotAfter: s.now().Add(time.Hour)},
		{Kind: "create-device", Name: "Expired", UserID: a.f.f.user.ID, Platform: "linux", NotAfter: s.now()},
		{Kind: "rename-device", TargetID: a.f.f.device.ID, Name: "Changed", Platform: "android"},
		{Kind: "rename-user", TargetID: a.f.f.user.ID, Name: a.f.f.user.Name},
		{Kind: "disable-user", TargetID: a.f.f.user.ID},
		{Kind: "disable-device", TargetID: a.f.f.device.ID},
		{Kind: "disable-connector", TargetID: a.f.f.connector.ID, Name: "unexpected"},
		{Kind: "disable-connector", TargetID: NewID()},
	} {
		before := summary(t, s)
		if _, err := p.Preview(ctx, a.conn, a.trust, lifecycleDraft(t, a, draft)); err == nil {
			t.Errorf("unsafe draft accepted: %s", draft.Kind)
		}
		if summary(t, s) != before {
			t.Fatal("rejected lifecycle draft changed state")
		}
	}
	request := lifecycleDraft(t, a, LifecycleDraft{Kind: "create-user", Name: "Stale request"})
	request.Lifecycle.PolicyRevision--
	if _, err := p.Preview(ctx, a.conn, a.trust, request); err == nil {
		t.Fatal("stale displayed policy accepted")
	}
	request = resourceDraft(a.f.f)
	request.Lifecycle = &LifecycleDraft{Kind: "create-user", Name: "Mixed draft", PolicyRevision: factorRevision(t, a)}
	if _, err := p.Preview(ctx, a.conn, a.trust, request); err == nil {
		t.Fatal("mixed resource/lifecycle operation accepted")
	}
	r := a.f.f.resource
	r.ID, r.Kind, r.Name = NewID(), "management", "Administrator delivery"
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddResource(r) }))
	if _, err := p.Preview(ctx, a.conn, a.trust, lifecycleDraft(t, a, LifecycleDraft{Kind: "disable-connector", TargetID: r.ConnectorID})); err == nil {
		t.Fatal("management connector could remove administrator delivery")
	}
}

func TestPolicyLifecycleApprovalRollbackAndTimeBound(t *testing.T) {
	for _, failure := range []string{"audit", "owner_disabled", "device_expiry"} {
		t.Run(failure, func(t *testing.T) {
			a := adminSeed(t)
			a.setupFactors(t)
			p, s := policyFixtureFor(t, a.f).engine, a.f.f.s
			owner := NewID()
			must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{ID: owner, Name: "Device owner", Enabled: true}) }))
			end := s.now().Add(30 * time.Second)
			view := previewPolicy(t, a, p, lifecycleDraft(t, a, LifecycleDraft{Kind: "create-device", Name: "Pending laptop", UserID: owner, Platform: "linux", NotAfter: end}))
			challenge := beginPolicy(t, a, p, view)
			proof := a.assertion(t, a.keys[0], challenge)
			switch failure {
			case "audit":
				_, err := s.db.Exec("CREATE TRIGGER reject_lifecycle_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
				must(t, err)
			case "owner_disabled":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("user", owner) }))
			case "device_expiry":
				s.now = func() time.Time { return end }
			}
			before := summary(t, s)
			if err := p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, challenge.ID, proof); err == nil {
				t.Fatal("invalid lifecycle confirmation committed")
			}
			if summary(t, s) != before {
				t.Fatal("failed lifecycle confirmation partially committed")
			}
			var count int
			must(t, s.db.QueryRow("SELECT count(*) FROM devices WHERE id=?", view.Lifecycle.ID).Scan(&count))
			if count != 0 {
				t.Fatal("failed confirmation created a device")
			}
			if failure == "audit" {
				_, err := s.db.Exec("DROP TRIGGER reject_lifecycle_audit")
				must(t, err)
				must(t, p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, challenge.ID, proof))
			}
		})
	}
}
