package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
)

func renewalHTTPApproval(t *testing.T, a *adminFixture, f *policyHTTPFixture) AdminRenewalPrepared {
	t.Helper()
	spec := a.renewalSpec(t)
	request := adminrenewal.PrepareRequest{Version: 1, RenewalID: NewID(), CSR: spec.CSR, NotAfter: spec.NotAfter, PolicyRevision: factorRevision(t, a)}
	var prepared AdminRenewalPrepared
	f.post(t, adminrenewal.PreparePath, request, &prepared)
	if prepared.Version != 1 || prepared.RenewalID != request.RenewalID || prepared.CSRHash != pki.Hash(spec.CSR) || prepared.CurrentCertificateHash != pki.Hash(a.identity.Certificate[0]) || prepared.PolicyRevision != request.PolicyRevision || !prepared.NotAfter.Equal(request.NotAfter) || !prepared.ExpiresAt.After(time.Now()) || prepared.ExpiresAt.After(time.Now().Add(2*time.Minute)) || prepared.Challenge.Approval == nil || prepared.Challenge.Registration != nil {
		t.Fatal("renewal review changed the approved identity, CSR or lifetime")
	}
	return prepared
}

func TestAdministratorRenewalHTTPSApprovalIssueRetrieveAndActivate(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p := policyFixtureFor(t, a.f)
	s := a.f.f.s
	var calls atomic.Int32
	provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
		calls.Add(1)
		return a.signRenewal(t, r), nil
	})
	config := PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier, AdministratorRenewalIssuer: provider}
	f := servePolicy(t, p.engine, config, a.identity)
	prepared := renewalHTTPApproval(t, a, f)
	proof := a.assertion(t, a.keys[1], prepared.Challenge)
	confirmation := adminrenewal.ConfirmRequest{Version: 1, ChallengeID: prepared.Challenge.ID, Response: proof}
	if calls.Load() != 0 {
		t.Fatal("preparation issued a certificate without hardware approval")
	}
	// Each existing administrative finish endpoint rejects the other operation.
	factorDenied(t, f, "/api/v1/admin/factors/confirm", finishApprovalRequest{ID: prepared.Challenge.ID, Response: proof}, nil)
	var result adminrenewal.Certificate
	f.post(t, adminrenewal.ConfirmPath, confirmation, &result)
	if result.Version != 1 || result.RenewalID != prepared.RenewalID || calls.Load() != 1 {
		t.Fatal("HTTP confirmation did not bind one restricted issuance")
	}
	credential, err := a.trust.Verify(result.CertificateDER, a.deviceID, s.now())
	must(t, err)
	if !credential.NotAfter.Equal(prepared.NotAfter) {
		t.Fatal("HTTP issuance changed the reviewed lifetime")
	}
	before := summary(t, s)
	factorDenied(t, f, adminrenewal.ConfirmPath, confirmation, nil)
	if calls.Load() != 1 || summary(t, s) != before {
		t.Fatal("confirmation replay signed or changed authority")
	}
	// Public certificate delivery remains available if issuer custody is offline.
	config.AdministratorRenewalIssuer = nil
	readOnly := servePolicy(t, p.engine, config, a.identity)
	var fetched adminrenewal.Certificate
	readOnly.post(t, adminrenewal.CertificatePath, adminrenewal.CertificateRequest{Version: 1, RenewalID: result.RenewalID}, &fetched)
	if !bytes.Equal(fetched.CertificateDER, result.CertificateDER) || summary(t, s) != before {
		t.Fatal("retrieval changed public signing evidence or issued again")
	}
	identity := tls.Certificate{Certificate: [][]byte{result.CertificateDER}, PrivateKey: a.identity.PrivateKey}
	activation := serveRenewalActivation(t, a)
	body, err := json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: result.RenewalID})
	must(t, err)
	status, _ := activation.request(t, activation.client(t, identity), body, nil)
	if status != http.StatusOK {
		t.Fatal("approved HTTPS renewal failed its separate activation")
	}
	if _, err = s.DashboardInventory(ctx, a.conn, a.trust, DashboardRequest{Section: "users", Limit: 1}); err == nil {
		t.Fatal("old administrator connection retained authority")
	}
	current := servePolicy(t, p.engine, config, identity)
	current.post(t, "/api/v1/admin/dashboard/inventory", DashboardRequest{Section: "users", Limit: 1}, nil)
	must(t, verifyAudit(ctx, s.db))
}

func TestAdministratorRenewalHTTPSRejectsStaleReviewAndWrongCapability(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p := policyFixtureFor(t, a.f)
	var calls atomic.Int32
	provider := issueFunc(func(context.Context, IssuanceRequest) ([]byte, error) { calls.Add(1); return nil, ErrDenied })
	config := PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier, AdministratorRenewalIssuer: provider}
	f := servePolicy(t, p.engine, config, a.identity)
	spec := a.renewalSpec(t)
	request := adminrenewal.PrepareRequest{Version: 1, RenewalID: NewID(), CSR: spec.CSR, NotAfter: spec.NotAfter, PolicyRevision: factorRevision(t, a)}
	for _, scenario := range []string{"version", "missing-revision", "stale-revision", "key", "scope-override", "origin"} {
		t.Run(scenario, func(t *testing.T) {
			changed := request
			var value any = changed
			var change func(*http.Request)
			switch scenario {
			case "version":
				changed.Version = 2
				value = changed
			case "missing-revision":
				changed.PolicyRevision = 0
				value = changed
			case "stale-revision":
				changed.PolicyRevision++
				value = changed
			case "key":
				changed.CSR = csrFor(t, newKey(t))
				value = changed
			case "scope-override":
				encoded, err := json.Marshal(changed)
				must(t, err)
				value = json.RawMessage(append(bytes.TrimSuffix(encoded, []byte("}")), []byte(`,"Profile":"device"}`)...))
			case "origin":
				change = func(r *http.Request) { r.Header.Del("Origin") }
			}
			before := summary(t, a.f.f.s)
			factorDenied(t, f, adminrenewal.PreparePath, value, change)
			if calls.Load() != 0 || summary(t, a.f.f.s) != before {
				t.Fatal("rejected renewal reached issuance or changed authority")
			}
		})
	}
	config.AdministratorRenewalIssuer = nil
	disabled := servePolicy(t, p.engine, config, a.identity)
	factorDenied(t, disabled, adminrenewal.PreparePath, request, nil)
	if _, err := p.engine.NewHTTPServer(PolicyHTTPConfig{Profile: pki.Device, AdministratorRenewalIssuer: provider}); err != ErrInvalid {
		t.Fatal("ordinary listener accepted administrator issuer capability")
	}
	prepared := renewalHTTPApproval(t, a, f)
	proof := a.assertion(t, a.keys[0], prepared.Challenge)
	must(t, a.f.f.s.Update(ctx, a.userID, func(tx *Tx) error { return tx.AddUser(User{ID: NewID(), Name: "New revision", Enabled: true}) }))
	factorDenied(t, f, adminrenewal.ConfirmPath, adminrenewal.ConfirmRequest{Version: 1, ChallengeID: prepared.Challenge.ID, Response: proof}, nil)
	if calls.Load() != 0 {
		t.Fatal("stale confirmation invoked the issuer")
	}
}

func TestAdministratorRenewalHTTPSPreservesAmbiguousIssuerResult(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	p := policyFixtureFor(t, a.f)
	var calls atomic.Int32
	results := make(chan []byte, 2)
	provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
		calls.Add(1)
		results <- a.signRenewal(t, r)
		return nil, errors.New("synthetic private issuer diagnostic")
	})
	f := servePolicy(t, p.engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: a.trust, AdministratorVerifier: a.verifier, AdministratorRenewalIssuer: provider}, a.identity)
	prepared := renewalHTTPApproval(t, a, f)
	confirmation := adminrenewal.ConfirmRequest{Version: 1, ChallengeID: prepared.Challenge.ID, Response: a.assertion(t, a.keys[0], prepared.Challenge)}
	factorDenied(t, f, adminrenewal.ConfirmPath, confirmation, nil)
	var signed []byte
	select {
	case signed = <-results:
	case <-time.After(time.Second):
		t.Fatal("ambiguous issuer did not retain its signed public result")
	}
	factorDenied(t, f, adminrenewal.ConfirmPath, confirmation, nil)
	factorDenied(t, f, adminrenewal.CertificatePath, adminrenewal.CertificateRequest{Version: 1, RenewalID: prepared.RenewalID}, nil)
	if calls.Load() != 1 || len(signed) == 0 {
		t.Fatal("uncertain HTTP issuance retried or lost public evidence")
	}
	must(t, a.f.f.s.ReconcileAdminRenewal(ctx, a.userID, prepared.RenewalID, a.trust, signed))
	var result adminrenewal.Certificate
	f.post(t, adminrenewal.CertificatePath, adminrenewal.CertificateRequest{Version: 1, RenewalID: prepared.RenewalID}, &result)
	if !bytes.Equal(result.CertificateDER, signed) || calls.Load() != 1 {
		t.Fatal("reconciliation changed the signed result or retried issuance")
	}
}
