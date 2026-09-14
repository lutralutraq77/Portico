package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func invitationRequest(t *testing.T, a *adminFixture, issuer *enrollmentFixture, principal string) InvitationRequest {
	t.Helper()
	now := a.f.f.s.now()
	return InvitationRequest{Kind: "invite", IssuerID: issuer.trust.IssuerID(), PrincipalID: principal, Profile: issuer.trust.Profile(), ExpiresAt: now.Add(5 * time.Minute), NotAfter: now.Add(30 * time.Minute).Truncate(time.Second), PolicyRevision: factorRevision(t, a)}
}

func TestDashboardInvitationHTTPCreateRedeemRevokeAndRedact(t *testing.T) {
	a := lifecycleAdminSeed(t)
	a.setupFactors(t)
	p, s := policyFixtureFor(t, a.f), a.f.f.s
	f := servePolicy(t, p.engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	for _, issuer := range []*enrollmentFixture{p.device, p.connector} {
		t.Run(string(issuer.trust.Profile()), func(t *testing.T) {
			principal := a.f.f.device.ID
			if issuer.trust.Profile() == pki.Connector {
				principal = a.f.f.connector.ID
			}
			request := invitationRequest(t, a, issuer, principal)
			var before, after int
			must(t, s.db.QueryRow("SELECT count(*) FROM enrollments").Scan(&before))
			var challenge InvitationChallenge
			f.post(t, "/api/v1/admin/invitations/challenge", request, &challenge)
			v := challenge.Invitation
			if !validID(v.ID) || v.PrincipalID != principal || v.IssuerID != request.IssuerID || v.Profile != request.Profile || v.PrincipalName == "" || !v.ExpiresAt.Equal(request.ExpiresAt) || !v.NotAfter.Equal(request.NotAfter) || v.State != "pending-approval" || challenge.Kind != "invite" || challenge.PolicyRevision != request.PolicyRevision || challenge.Challenge.Approval == nil || challenge.Challenge.Registration != nil {
				t.Fatal("challenge changed the reviewed invitation")
			}
			must(t, s.db.QueryRow("SELECT count(*) FROM enrollments").Scan(&after))
			if after != before {
				t.Fatal("challenge created an enrollment before hardware approval")
			}
			if v.Profile == pki.Device && (v.UserID != a.f.f.user.ID || v.UserName != a.f.f.user.Name) {
				t.Fatal("device owner missing from review")
			}
			proof := a.assertion(t, a.keys[0], challenge.Challenge)
			// The approving response contains no resubmitted spec to mutate.
			request.PrincipalID, request.IssuerID = NewID(), NewID()
			var result InvitationResult
			f.post(t, "/api/v1/admin/invitations/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, &result)
			if result.ID != v.ID || len(result.Secret) != 43 {
				t.Fatal("approved invitation did not return its one-time secret")
			}
			var hash, storedPrincipal string
			must(t, s.db.QueryRow("SELECT token_hash,coalesce(device_id,connector_id) FROM enrollments WHERE id=?", result.ID).Scan(&hash, &storedPrincipal))
			if !validSecret(result.Secret, hash) || storedPrincipal != principal || hash == result.Secret {
				t.Fatal("stored invitation did not bind a hashed secret and exact principal")
			}
			for _, section := range []string{"enrollments", "audit", "security"} {
				page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: section, Limit: 50})
				must(t, err)
				body, err := json.Marshal(page)
				must(t, err)
				if bytes.Contains(body, []byte(result.Secret)) || bytes.Contains(body, []byte(hash)) || strings.Contains(string(body), "token_hash") {
					t.Fatal("metadata exposed invitation secret material")
				}
			}
			state := summary(t, s)
			factorDenied(t, f, "/api/v1/admin/invitations/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, nil)
			if summary(t, s) != state {
				t.Fatal("replay changed invitation state")
			}
			// Redeem the actual approved token, sign a real profile-restricted leaf,
			// activate with its TLS key, then revoke through the private HTTP route.
			key, attempt := newKey(t), NewID()
			csr := csrFor(t, key)
			must(t, s.ReserveEnrollment(ctx, a.f.f.actor, result.ID, result.Secret, attempt, csr))
			must(t, s.IssueEnrollment(ctx, a.f.f.actor, result.ID, issuer.trust, issuer.provider(t)))
			der, err := s.EnrollmentCertificate(ctx, a.f.f.actor, result.ID, result.Secret, attempt, csr)
			must(t, err)
			identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			conn, err := tlsHandshake(t, s, issuer.trust, identity, true)
			must(t, err)
			must(t, s.ActivateEnrollment(ctx, result.ID, conn, issuer.trust))
			f.post(t, "/api/v1/admin/invitations/challenge", InvitationRequest{Kind: "revoke-enrollment", EnrollmentID: result.ID, PolicyRevision: factorRevision(t, a)}, &challenge)
			if challenge.Invitation.State != "active" || challenge.Invitation.ID != result.ID || challenge.Invitation.PrincipalID != principal {
				t.Fatal("revocation review lost the current enrollment identity or state")
			}
			var revoked InvitationResult
			f.post(t, "/api/v1/admin/invitations/confirm", finishApprovalRequest{challenge.Challenge.ID, a.assertion(t, a.keys[0], challenge.Challenge)}, &revoked)
			if revoked.ID != result.ID || revoked.Secret != "" {
				t.Fatal("revocation revealed a secret or changed its identity")
			}
			if _, err := tlsHandshake(t, s, issuer.trust, identity, false); err == nil {
				t.Fatal("revoked enrollment still authenticated with its real TLS key")
			}
			if err := s.ReserveEnrollment(ctx, a.f.f.actor, result.ID, result.Secret, NewID(), csr); err == nil {
				t.Fatal("revocation allowed invitation reuse")
			}
			factorDenied(t, f, "/api/v1/admin/invitations/challenge", InvitationRequest{Kind: "revoke-enrollment", EnrollmentID: result.ID, PolicyRevision: factorRevision(t, a)}, nil)
		})
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestDashboardInvitationRejectsMalformedProfileOriginAndScope(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p, s := policyFixtureFor(t, a.f), a.f.f.s
	f := servePolicy(t, p.engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier}, a.identity)
	for name, mutate := range map[string]func(*InvitationRequest){
		"unknown_kind":               func(r *InvitationRequest) { r.Kind = "register-factor" },
		"caller_id":                  func(r *InvitationRequest) { r.EnrollmentID = NewID() },
		"admin_profile":              func(r *InvitationRequest) { r.Profile = pki.Administrator },
		"wrong_issuer_profile":       func(r *InvitationRequest) { r.IssuerID = p.connector.trust.IssuerID() },
		"missing_principal":          func(r *InvitationRequest) { r.PrincipalID = NewID() },
		"missing_issuer":             func(r *InvitationRequest) { r.IssuerID = NewID() },
		"stale_revision":             func(r *InvitationRequest) { r.PolicyRevision-- },
		"expired_token":              func(r *InvitationRequest) { r.ExpiresAt = s.now() },
		"long_token":                 func(r *InvitationRequest) { r.ExpiresAt = s.now().Add(2 * time.Hour) },
		"expired_identity":           func(r *InvitationRequest) { r.NotAfter = s.now().Add(-time.Second) },
		"identity_beyond_authority":  func(r *InvitationRequest) { r.NotAfter = s.now().Add(6 * time.Hour).Truncate(time.Second) },
		"fractional_identity_expiry": func(r *InvitationRequest) { r.NotAfter = r.NotAfter.Add(time.Nanosecond) },
		"mixed_revoke":               func(r *InvitationRequest) { r.Kind, r.EnrollmentID = "revoke-enrollment", NewID() },
	} {
		t.Run(name, func(t *testing.T) {
			request := invitationRequest(t, a, p.device, a.f.f.device.ID)
			mutate(&request)
			before := summary(t, s)
			factorDenied(t, f, "/api/v1/admin/invitations/challenge", request, nil)
			if summary(t, s) != before {
				t.Fatal("invalid request changed state")
			}
		})
	}
	request := invitationRequest(t, a, p.device, a.f.f.device.ID)
	for _, origin := range []string{"", "https://other.portico.test", "null"} {
		factorDenied(t, f, "/api/v1/admin/invitations/challenge", request, func(r *http.Request) { r.Header.Set("Origin", origin) })
	}
	data, err := json.Marshal(request)
	must(t, err)
	var extra map[string]any
	must(t, json.Unmarshal(data, &extra))
	extra["Secret"] = "caller-owned-token"
	factorDenied(t, f, "/api/v1/admin/invitations/challenge", extra, nil)
	var challenge InvitationChallenge
	f.post(t, "/api/v1/admin/invitations/challenge", request, &challenge)
	proof := a.assertion(t, a.keys[0], challenge.Challenge)
	for _, path := range []string{"/api/v1/admin/factors/confirm", "/api/v1/admin/policy/confirm"} {
		before := summary(t, s)
		factorDenied(t, f, path, finishApprovalRequest{challenge.Challenge.ID, proof}, nil)
		if summary(t, s) != before {
			t.Fatal("foreign endpoint consumed invitation")
		}
	}
	var result InvitationResult
	f.post(t, "/api/v1/admin/invitations/confirm", finishApprovalRequest{challenge.Challenge.ID, proof}, &result)
	for _, kind := range []string{"test-factor", "register-factor"} {
		op := AdminOperation{Kind: kind, TargetID: a.factors[0]}
		ceremony, err := s.BeginAdminOperation(ctx, a.conn, a.trust, a.verifier, op)
		must(t, err)
		before := summary(t, s)
		factorDenied(t, f, "/api/v1/admin/invitations/confirm", finishApprovalRequest{ceremony.ID, a.assertion(t, a.keys[0], ceremony)}, nil)
		if summary(t, s) != before {
			t.Fatal("invitation endpoint consumed factor operation")
		}
	}
	view := previewPolicy(t, a, p.engine, resourceDraft(a.f.f))
	ceremony := beginPolicy(t, a, p.engine, view)
	factorDenied(t, f, "/api/v1/admin/invitations/confirm", finishApprovalRequest{ceremony.ID, a.assertion(t, a.keys[0], ceremony)}, nil)
	ordinary := servePolicy(t, p.engine, PolicyHTTPConfig{Profile: pki.Device, Host: "device.portico.test"}, p.deviceIdentity)
	factorDenied(t, ordinary, "/api/v1/admin/invitations/challenge", request, nil)
}

func TestDashboardInvitationApprovalRollbackExpiryAndRevocation(t *testing.T) {
	for _, failure := range []string{"audit", "invitation_expiry", "device_revocation", "issuer_revocation", "admin_revocation", "tested_backup_removed", "invalid_proof"} {
		t.Run(failure, func(t *testing.T) {
			a := lifecycleAdminSeed(t)
			a.setupFactors(t)
			s := a.f.f.s
			request := invitationRequest(t, a, a.f, a.f.f.device.ID)
			request.ExpiresAt = s.now().Add(20 * time.Second)
			challenge, err := s.BeginInvitation(ctx, a.conn, a.trust, a.verifier, request)
			must(t, err)
			proof := a.assertion(t, a.keys[0], challenge.Challenge)
			switch failure {
			case "audit":
				_, err = s.db.Exec("CREATE TRIGGER reject_invitation_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
				must(t, err)
			case "invitation_expiry":
				s.now = func() time.Time { return request.ExpiresAt }
			case "device_revocation":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
			case "issuer_revocation":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("issuer", a.f.trust.IssuerID()) }))
			case "admin_revocation":
				must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.deviceID) }))
			case "tested_backup_removed":
				_, err = s.db.Exec("UPDATE admin_factors SET tested=0 WHERE id=?", a.factors[1])
				must(t, err)
			case "invalid_proof":
				proof = []byte(`{}`)
			}
			before := summary(t, s)
			result, err := s.FinishInvitation(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, proof)
			if err == nil || result.ID != "" || result.Secret != "" {
				t.Fatal("failed approval returned an invitation or secret")
			}
			if summary(t, s) != before {
				t.Fatal("failed approval partially committed")
			}
			var count int
			must(t, s.db.QueryRow("SELECT count(*) FROM enrollments WHERE id=?", challenge.Invitation.ID).Scan(&count))
			if count != 0 {
				t.Fatal("failed approval left an enrollment")
			}
			if failure == "audit" {
				_, err = s.db.Exec("DROP TRIGGER reject_invitation_audit")
				must(t, err)
				_, err = s.FinishInvitation(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, proof)
				must(t, err)
			}
		})
	}
}

func TestDashboardInvitationRevocationLockoutAndTwoKeyRequirement(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	request := invitationRequest(t, a, a.f, a.deviceID)
	if _, err := s.BeginInvitation(ctx, a.conn, a.trust, a.verifier, request); err == nil {
		t.Fatal("invitation approved before two tested keys")
	}
	a.setupFactors(t)
	p := policyFixtureFor(t, a.f)
	var self, connector string
	must(t, s.db.QueryRow("SELECT id FROM enrollments WHERE device_id=?", a.deviceID).Scan(&self))
	must(t, s.db.QueryRow("SELECT id FROM enrollments WHERE connector_id=?", a.f.f.connector.ID).Scan(&connector))
	request = InvitationRequest{Kind: "revoke-enrollment", EnrollmentID: self, PolicyRevision: factorRevision(t, a)}
	if _, err := s.BeginInvitation(ctx, a.conn, a.trust, a.verifier, request); err == nil {
		t.Fatal("administrator could revoke own enrollment")
	}
	request.EnrollmentID = connector
	challenge, err := s.BeginInvitation(ctx, a.conn, a.trust, a.verifier, request)
	must(t, err)
	proof := a.assertion(t, a.keys[0], challenge.Challenge)
	r := a.f.f.resource
	r.ID, r.Kind = NewID(), "management"
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddResource(r) }))
	if _, err := s.FinishInvitation(ctx, a.conn, a.trust, a.verifier, challenge.Challenge.ID, proof); err == nil {
		t.Fatal("late management binding did not stop revocation")
	}
	request.PolicyRevision = factorRevision(t, a)
	if _, err := s.BeginInvitation(ctx, a.conn, a.trust, a.verifier, request); err == nil {
		t.Fatal("management connector enrollment could be revoked")
	}
	if _, err := p.engine.Authorize(ctx, p.connectorConn, p.request()); err != nil {
		t.Fatal("denied administrator operation damaged existing workload authority")
	}
}

func TestDashboardInvitationIssuerInventoryIsBoundAndMetadataOnly(t *testing.T) {
	a := adminSeed(t)
	p, s := policyFixtureFor(t, a.f), a.f.f.s
	before := summary(t, s)
	for _, issuer := range []*enrollmentFixture{p.device, p.connector} {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "issuers", Profile: string(issuer.trust.Profile()), Limit: 50})
		must(t, err)
		items := page.Items.([]DashboardIssuer)
		if len(items) != 1 || items[0].ID != issuer.trust.IssuerID() || items[0].Profile != string(issuer.trust.Profile()) || items[0].Fingerprint != issuer.trust.IssuerFingerprint() || items[0].RootFingerprint != issuer.trust.RootFingerprint() || !items[0].Enabled || !items[0].NotAfter.Equal(issuer.trust.NotAfter()) {
			t.Fatal("issuer metadata differs from the bound trust")
		}
	}
	request := DashboardRequest{Section: "issuers", Limit: 1}
	seen := map[string]bool{}
	for range 2 {
		page, err := s.DashboardInventory(ctx, a.conn, a.trust, request)
		must(t, err)
		items := page.Items.([]DashboardIssuer)
		if len(items) != 1 || seen[items[0].ID] {
			t.Fatal("issuer pagination repeated or omitted a record")
		}
		seen[items[0].ID] = true
		request.After, request.PolicyRevision = page.Next, page.PolicyRevision
	}
	if request.After != "" {
		t.Fatal("issuer pagination did not terminate")
	}
	for _, profile := range []string{"administrator", "device' OR 1=1 --"} {
		if _, err := s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "issuers", Profile: profile, Limit: 50}); err == nil {
			t.Fatal("invalid issuer profile was accepted")
		}
	}
	if summary(t, s) != before {
		t.Fatal("issuer inventory changed state")
	}
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("issuer", p.connector.trust.IssuerID()) }))
	if _, err := s.DashboardInventory(ctx, a.conn, a.trust, request); err == nil {
		t.Fatal("stale issuer inventory revision accepted")
	}
}
