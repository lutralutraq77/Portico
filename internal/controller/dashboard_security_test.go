package controller

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func TestDashboardAuditChronologyAndNonMutatingPagination(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	expected, err := s.AuditBatch(ctx, Checkpoint{}, 256)
	must(t, err)
	if len(expected) < 4 || len(expected) >= 256 {
		t.Fatal("fixture must span several bounded pages")
	}
	before := summary(t, s)
	var exportBefore Checkpoint
	must(t, s.db.QueryRow("SELECT export_sequence,export_hash FROM meta WHERE singleton=1").Scan(&exportBefore.Sequence, &exportBefore.Hash))
	request := DashboardRequest{Section: "audit", Limit: 2}
	var got []DashboardAudit
	for range len(expected) {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, request)
		must(t, err)
		items := page.Items.([]DashboardAudit)
		if len(items) > 2 || page.ObservedAt.IsZero() {
			t.Fatal("invalid audit page")
		}
		got = append(got, items...)
		if page.Next == "" {
			break
		}
		if len(items) != 2 || page.Next != items[len(items)-1].ID {
			t.Fatal("audit cursor did not identify the last returned event")
		}
		request.After, request.PolicyRevision = page.Next, page.PolicyRevision
	}
	var want []DashboardAudit
	for _, event := range expected {
		want = append(want, DashboardAudit{ID: event.ID, ActorID: event.ActorID, CorrelationID: event.CorrelationID, Action: event.Action, TargetID: event.TargetID, PreviousHash: event.PreviousHash, Hash: event.Hash, Sequence: event.Sequence, Generation: event.Generation, OccurredAt: time.Unix(0, event.OccurredAt).UTC()})
	}
	var exportAfter Checkpoint
	must(t, s.db.QueryRow("SELECT export_sequence,export_hash FROM meta WHERE singleton=1").Scan(&exportAfter.Sequence, &exportAfter.Hash))
	if !reflect.DeepEqual(got, want) || before != summary(t, s) || exportAfter != exportBefore {
		t.Fatal("audit pages changed, omitted, reordered or acknowledged history")
	}
	request.After = NewID()
	if page, err := s.DashboardInventory(ctx, a.conn, a.trust, request); err == nil || page.Items != nil {
		t.Fatal("unknown audit cursor restarted or exposed a page")
	}
}

func TestDashboardSecurityUsesCurrentAdministratorAndFactorState(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	read := func() DashboardSecurity {
		t.Helper()
		before := summary(t, s)
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "security", Limit: 2})
		must(t, err)
		items := page.Items.([]DashboardSecurity)
		if len(items) != 1 || page.Next != "" || summary(t, s) != before {
			t.Fatal("security read was not a single nonmutating administrator record")
		}
		return items[0]
	}
	v := read()
	if v.ID != a.f.f.user.ID || v.UserName != a.f.f.user.Name || v.DeviceID != a.f.f.device.ID || v.DeviceName != a.f.f.device.Name || v.CertificateFingerprint != pki.Hash(a.identity.Certificate[0]) || v.EnabledFactors != 0 || v.TestedEnabledFactors != 0 || !v.CertificateExpiresAt.After(time.Now()) || v.BootstrapUntil.IsZero() {
		t.Fatal("security record did not match the presented identity")
	}
	a.setupFactors(t)
	v = read()
	if v.EnabledFactors != 2 || v.TestedEnabledFactors != 2 {
		t.Fatal("tested factors were not reflected")
	}
	// A separate owner's opaque credential is deliberately never decoded or
	// exposed by this administrator-scoped metadata query.
	other := NewID()
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{other, "Another owner", true}) }))
	_, err := s.db.Exec("INSERT INTO admin_factors VALUES(?,?,?,?,?,1,1)", NewID(), other, []byte("other fixture credential"), []byte("other fixture public key"), []byte("other fixture credential body"))
	must(t, err)
	_, err = s.db.Exec("UPDATE admin_factors SET enabled=0 WHERE id=?", a.factors[0])
	must(t, err)
	v = read()
	if v.EnabledFactors != 1 || v.TestedEnabledFactors != 1 {
		t.Fatal("disabled or another owner's factors entered the current count")
	}
}

func TestDashboardAuditRejectsCorruptHistory(t *testing.T) {
	for _, kind := range []string{"changed_event", "missing_event", "changed_head"} {
		t.Run(kind, func(t *testing.T) {
			a := adminSeed(t)
			s := a.f.f.s
			var statement string
			switch kind {
			case "changed_event":
				statement = "DROP TRIGGER audit_no_update; UPDATE audit_events SET action='altered' WHERE sequence=1"
			case "missing_event":
				statement = "DROP TRIGGER audit_no_delete; DELETE FROM audit_events WHERE sequence=1"
			case "changed_head":
				statement = "UPDATE meta SET audit_hash='' WHERE singleton=1"
			}
			_, err := s.db.Exec(statement)
			must(t, err)
			if page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "audit", Limit: 2}); err == nil || page.Items != nil {
				t.Fatal("corrupt audit history was displayed")
			}
		})
	}
}

func TestDashboardAuditSecurityRecheckLiveTLSAuthority(t *testing.T) {
	a := adminSeed(t)
	f := servePolicy(t, policyFixtureFor(t, a.f).engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	for _, section := range []string{"audit", "security"} {
		body, err := json.Marshal(DashboardRequest{Section: section, Limit: 2})
		must(t, err)
		response, _, _ := dashboardHTTP(t, f, string(body), "https://"+f.host)
		if response.StatusCode != http.StatusOK {
			t.Fatal("authenticated audit/security control failed")
		}
	}
	must(t, a.f.f.s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
	for _, section := range []string{"audit", "security"} {
		body, err := json.Marshal(DashboardRequest{Section: section, Limit: 2})
		must(t, err)
		response, data, reused := dashboardHTTP(t, f, string(body), "https://"+f.host)
		if !reused || response.StatusCode != http.StatusForbidden || string(data) != `{"error":"request rejected"}` {
			t.Fatal("revoked administrator retained audit or security data")
		}
	}
}
