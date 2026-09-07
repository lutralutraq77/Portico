package controller

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func resourceDraft(f fixture) PolicyDraft {
	return PolicyDraft{Resource: &ResourceDraft{Name: "New application", ConnectorID: f.connector.ID, Address: "192.168.50.11", Port: 8443, Protocol: "tcp"}}
}

func previewPolicy(t *testing.T, a *adminFixture, p *PolicyEngine, d PolicyDraft) PolicyPreview {
	t.Helper()
	v, e := p.Preview(ctx, a.conn, a.trust, d)
	must(t, e)
	return v
}

func beginPolicy(t *testing.T, a *adminFixture, p *PolicyEngine, v PolicyPreview) AdminChallenge {
	t.Helper()
	c, e := p.BeginPolicyApproval(ctx, a.conn, a.trust, a.verifier, v.ID, v.Digest)
	must(t, e)
	return c
}

func applyPolicy(t *testing.T, a *adminFixture, p *PolicyEngine, d PolicyDraft) PolicyPreview {
	t.Helper()
	v := previewPolicy(t, a, p, d)
	c := beginPolicy(t, a, p, v)
	must(t, p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, c.ID, a.assertion(t, a.keys[0], c)))
	return v
}

func TestPolicyPreviewExactHardwareApprovalAndOneUse(t *testing.T) {
	a := adminSeed(t)
	v := policyFixtureFor(t, a.f)
	p, s := v.engine, a.f.f.s
	d := resourceDraft(a.f.f)
	preview := previewPolicy(t, a, p, d)
	if _, e := p.BeginPolicyApproval(ctx, a.conn, a.trust, a.verifier, preview.ID, preview.Digest); e == nil {
		t.Fatal("factorless policy approval")
	}
	a.setupFactors(t)
	// Adding the two factors changed authority, so the original preview is stale.
	if _, e := p.BeginPolicyApproval(ctx, a.conn, a.trust, a.verifier, preview.ID, preview.Digest); e == nil {
		t.Fatal("preview survived factor registration")
	}
	preview = previewPolicy(t, a, p, d)
	if preview.Resource.ConnectorName != a.f.f.connector.Name || preview.Resource.Address != d.Resource.Address || preview.Resource.Port != d.Resource.Port || preview.Digest == "" {
		t.Fatal("preview omitted effective endpoint or digest")
	}
	d.Resource.Address = "192.168.50.12"
	d.Resource.Port = 22
	c := beginPolicy(t, a, p, preview)
	response := a.assertion(t, a.keys[0], c)
	if _, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
		t.Fatal("generic administrator completion bypassed policy callback")
	}
	// Normal session/audit traffic must not invalidate a pending approval.
	permit, e := p.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	active, e := p.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: permit.Sequence})
	must(t, e)
	_, e = p.Renew(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: active.Sequence})
	must(t, e)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, c.ID, response) })
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("approval committed %d times", successes)
	}
	var address string
	var port, grants int
	must(t, s.db.QueryRow("SELECT address,port FROM resources WHERE id=?", preview.Resource.ID).Scan(&address, &port))
	must(t, s.db.QueryRow("SELECT count(*) FROM grants WHERE resource_id=?", preview.Resource.ID).Scan(&grants))
	if address != preview.Resource.Address || port != preview.Resource.Port || grants != 0 {
		t.Fatal("stored preview mutated or implicitly granted access")
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestPolicyPreviewStalenessAndAtomicFailure(t *testing.T) {
	for _, kind := range []string{"authority_changed", "endpoint_changed", "config_changed", "digest_changed", "expired_preview", "expired_challenge", "device_revoked", "audit_failure", "wrong_operation"} {
		t.Run(kind, func(t *testing.T) {
			a := adminSeed(t)
			p := policyFixtureFor(t, a.f).engine
			a.setupFactors(t)
			s := a.f.f.s
			v := previewPolicy(t, a, p, resourceDraft(a.f.f))
			c := beginPolicy(t, a, p, v)
			response := a.assertion(t, a.keys[0], c)
			switch kind {
			case "authority_changed":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Another user", true}) }))
			case "endpoint_changed":
				r := a.f.f.resource
				r.Revision++
				r.Port = 22
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.ReviseResource(1, r) }))
			case "config_changed":
				cfg := p.config
				cfg.MaxSessions++
				var e error
				p, e = NewPolicyEngine(s, cfg)
				must(t, e)
			case "digest_changed":
				if _, e := p.BeginPolicyApproval(ctx, a.conn, a.trust, a.verifier, v.ID, strings.Repeat("f", 64)); e == nil {
					t.Fatal("different preview digest accepted")
				}
				// A modification of persisted content cannot inherit the old digest.
				_, e := s.db.Exec("UPDATE policy_previews SET display_json=? WHERE id=?", []byte(`{}`), v.ID)
				must(t, e)
			case "expired_preview":
				s.now = func() time.Time { return v.ExpiresAt }
			case "expired_challenge":
				var expires int64
				must(t, s.db.QueryRow("SELECT expires_at FROM admin_ceremonies WHERE id=?", c.ID).Scan(&expires))
				now := time.Unix(0, expires)
				s.now = func() time.Time { return now }
			case "device_revoked":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
			case "audit_failure":
				_, e := s.db.Exec("CREATE TRIGGER reject_policy_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
				must(t, e)
			case "wrong_operation":
				c = a.begin(t, a.invitation())
				response = a.assertion(t, a.keys[0], c)
			}
			before := summary(t, s)
			var oldFactor []byte
			must(t, s.db.QueryRow("SELECT credential_json FROM admin_factors WHERE id=?", a.factors[0]).Scan(&oldFactor))
			if e := p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
				t.Fatal("invalid approval committed")
			}
			var count int
			var state string
			var factor []byte
			must(t, s.db.QueryRow("SELECT count(*) FROM resources WHERE id=?", v.Resource.ID).Scan(&count))
			must(t, s.db.QueryRow("SELECT state FROM admin_ceremonies WHERE id=?", c.ID).Scan(&state))
			must(t, s.db.QueryRow("SELECT credential_json FROM admin_factors WHERE id=?", a.factors[0]).Scan(&factor))
			if count != 0 || state != "pending" || string(factor) != string(oldFactor) || summary(t, s) != before {
				t.Fatal("failed approval partially committed")
			}
			if kind == "audit_failure" {
				_, e := s.db.Exec("DROP TRIGGER reject_policy_audit")
				must(t, e)
				must(t, p.FinishPolicyApproval(ctx, a.conn, a.trust, a.verifier, c.ID, response))
			}
		})
	}
}

func TestPolicyHardwareApprovedGrantHostingAndRevision(t *testing.T) {
	a := adminSeed(t)
	v := policyFixtureFor(t, a.f)
	a.setupFactors(t)
	p, f := v.engine, a.f.f
	resource := applyPolicy(t, a, p, resourceDraft(f)).Resource
	r := v.request()
	r.ResourceID = resource.ID
	if _, e := p.Authorize(ctx, v.connectorConn, r); e == nil {
		t.Fatal("resource implicitly granted")
	}
	applyPolicy(t, a, p, PolicyDraft{Hosting: &HostingDraft{ConnectorID: resource.ConnectorID, ResourceID: resource.ID, Revision: resource.Revision, From: f.s.now(), Until: f.grant.Until}})
	if _, e := p.Authorize(ctx, v.connectorConn, r); e == nil {
		t.Fatal("hosting implicitly granted device access")
	}
	d := PolicyDraft{Grant: &GrantDraft{UserID: f.user.ID, DeviceID: f.device.ID, ResourceID: resource.ID, Revision: resource.Revision, From: f.s.now(), Until: f.grant.Until}}
	view := applyPolicy(t, a, p, d)
	if view.UserName != f.user.Name || view.DeviceName != f.device.Name || view.DeviceID != f.device.ID || view.Until != f.grant.Until {
		t.Fatal("grant preview omitted effective identity/deadline")
	}
	permit, e := p.Authorize(ctx, v.connectorConn, r)
	must(t, e)
	if _, e = p.Preview(ctx, a.conn, a.trust, d); e == nil {
		t.Fatal("overlapping grant preview accepted")
	}
	d = resourceDraft(f)
	d.ResourceID = resource.ID
	d.ExpectedRevision = 1
	d.Resource.Port = 22
	revised := applyPolicy(t, a, p, d)
	if revised.Previous == nil || revised.Previous.Port != 8443 || revised.Resource.Port != 22 || revised.Resource.Revision != 2 {
		t.Fatal("revision preview did not expose old/new endpoint")
	}
	if _, e = p.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: permit.Sequence}); e == nil {
		t.Fatal("revision left old session usable")
	}
	r.Revision = 2
	if _, e = p.Authorize(ctx, v.connectorConn, r); e == nil {
		t.Fatal("new revision inherited access or hosting")
	}
	must(t, verifyAudit(ctx, f.s.db))
}

func TestPolicyPreviewRejectsUnsafeAndAmbiguousDrafts(t *testing.T) {
	a := adminSeed(t)
	p := policyFixtureFor(t, a.f).engine
	for _, kind := range []string{"empty", "multiple", "hostname", "loopback", "protected", "udp", "all_ports", "management_fields", "wrong_connector", "wrong_owner", "unenrolled_device", "device_expiry", "hosting_mismatch", "overlapping_host"} {
		t.Run(kind, func(t *testing.T) {
			f := a.f.f
			d := resourceDraft(f)
			switch kind {
			case "empty":
				d = PolicyDraft{}
			case "multiple":
				d.Grant = &GrantDraft{}
			case "hostname":
				d.Resource.Address = "example.test"
			case "loopback":
				d.Resource.Address = "127.0.0.1"
			case "protected":
				d.Resource.Address = "10.99.0.2"
			case "udp":
				d.Resource.Protocol = "udp"
			case "all_ports":
				d.Resource.Port = 0
			case "management_fields":
				d.ExpectedRevision = 2
			case "wrong_connector":
				d.Resource.ConnectorID = NewID()
			case "wrong_owner", "unenrolled_device", "device_expiry":
				d = PolicyDraft{Grant: &GrantDraft{UserID: f.user.ID, DeviceID: f.device.ID, ResourceID: f.resource.ID, Revision: 1, From: f.s.now(), Until: f.grant.Until}}
				if kind == "wrong_owner" {
					d.Grant.UserID = NewID()
				}
				if kind == "unenrolled_device" {
					device := Device{ID: NewID(), UserID: f.user.ID, Name: "Unenrolled", Platform: "linux", Enabled: true, NotAfter: f.device.NotAfter}
					must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddDevice(device) }))
					d.Grant.DeviceID = device.ID
				}
				if kind == "device_expiry" {
					d.Grant.Until = f.device.NotAfter.Add(time.Minute)
				}
			case "hosting_mismatch", "overlapping_host":
				d = PolicyDraft{Hosting: &HostingDraft{ConnectorID: f.connector.ID, ResourceID: f.resource.ID, Revision: 1, From: f.s.now(), Until: f.grant.Until}}
				if kind == "hosting_mismatch" {
					d.Hosting.ConnectorID = NewID()
				}
			}
			before := summary(t, f.s)
			if _, e := p.Preview(ctx, a.conn, a.trust, d); e == nil {
				t.Fatal("unsafe draft accepted")
			}
			if summary(t, f.s) != before {
				t.Fatal("invalid preview committed")
			}
		})
	}
}
