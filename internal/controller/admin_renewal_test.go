package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func (a *adminFixture) renewalSpec(t *testing.T) AdminRenewalSpec {
	t.Helper()
	return AdminRenewalSpec{CSR: csrFor(t, a.identity.PrivateKey.(*ecdsa.PrivateKey)), NotAfter: a.f.f.s.now().Add(90 * time.Minute)}
}

func (a *adminFixture) approveRenewal(t *testing.T) string {
	t.Helper()
	id := NewID()
	s := a.f.f.s
	c, err := s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, id, a.renewalSpec(t))
	must(t, err)
	result, err := s.FinishAdminRenewal(ctx, a.conn, a.trust, a.verifier, c.ID, a.assertion(t, a.keys[0], c))
	must(t, err)
	if result != id {
		t.Fatal("renewal did not retain the approved identifier")
	}
	return id
}

func (a *adminFixture) signRenewal(t *testing.T, request IssuanceRequest) []byte {
	t.Helper()
	if request.Profile != pki.Administrator || request.PrincipalID != a.deviceID || request.DeploymentID != a.trust.DeploymentID() || request.IssuerID != a.trust.IssuerID() || !validID(request.AttemptID) {
		t.Fatal("issuer received substituted authority")
	}
	f := &enrollmentFixture{ca: a.ca, caKey: a.caKey}
	return f.sign(t, request)
}

func (a *adminFixture) issueRenewal(t *testing.T, id string) tls.Certificate {
	t.Helper()
	s := a.f.f.s
	must(t, s.IssueAdminRenewal(ctx, a.userID, id, a.trust, issueFunc(func(_ context.Context, request IssuanceRequest) ([]byte, error) {
		return a.signRenewal(t, request), nil
	})))
	der, err := s.AdminRenewalCertificate(ctx, a.conn, a.trust, id)
	must(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.identity.PrivateKey}
}

func TestAdministratorRenewalRequiresFreshHardwareAndSeparateTLSActivation(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	id := NewID()
	spec := a.renewalSpec(t)
	c, err := s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, id, spec)
	must(t, err)
	response := a.assertion(t, a.keys[0], c)
	if _, err = s.FinishFactor(ctx, a.conn, a.trust, a.verifier, c.ID, response); err == nil {
		t.Fatal("factor endpoint consumed a renewal")
	}
	if _, err = s.FinishInvitation(ctx, a.conn, a.trust, a.verifier, c.ID, response); err == nil {
		t.Fatal("invitation endpoint consumed a renewal")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if result, err := s.FinishAdminRenewal(ctx, a.conn, a.trust, a.verifier, c.ID, response); err == nil {
				if result != id {
					t.Error("wrong renewal result")
				}
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("hardware approval was not consumed exactly once")
	}
	// Caller mutation cannot change the stored, hardware-approved CSR/lifetime.
	spec.CSR[0] ^= 1
	spec.NotAfter = spec.NotAfter.Add(time.Hour)
	var calls atomic.Int32
	provider := issueFunc(func(_ context.Context, request IssuanceRequest) ([]byte, error) {
		calls.Add(1)
		if request.AttemptID != id || !request.NotAfter.Equal(s.now().Add(90*time.Minute)) {
			t.Error("approved issuer scope changed")
		}
		return a.signRenewal(t, request), nil
	})
	successes.Store(0)
	for range 2 {
		wg.Go(func() {
			if s.IssueAdminRenewal(ctx, a.userID, id, a.trust, provider) == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || successes.Load() != 1 {
		t.Fatal("signing attempt was not singular")
	}
	der, err := s.AdminRenewalCertificate(ctx, a.conn, a.trust, id)
	must(t, err)
	identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.identity.PrivateKey}
	if _, err = tlsHandshake(t, s, a.trust, identity, false); err == nil {
		t.Fatal("unactivated leaf entered the administrator listener")
	}
	if _, err = tlsHandshake(t, s, a.f.trust, identity, true); err == nil {
		t.Fatal("administrator renewal entered ordinary enrollment")
	}
	wrong := identity
	wrong.PrivateKey = newKey(t)
	if _, err = tlsHandshake(t, s, a.trust, wrong, true); err == nil {
		t.Fatal("candidate authenticated without its private key")
	}
	if err = s.ActivateAdminRenewal(ctx, a.conn, a.trust, id); err == nil {
		t.Fatal("old certificate activated a replacement")
	}
	candidate, err := tlsHandshake(t, s, a.trust, identity, true)
	must(t, err)
	if _, err = s.BeginAdminOperation(ctx, candidate, a.trust, a.verifier, a.invitation()); err == nil {
		t.Fatal("activation-only connection administered the controller")
	}
	if err = s.ActivateAdminRenewal(ctx, candidate, a.trust, NewID()); err == nil {
		t.Fatal("candidate activated another reservation")
	}
	stale := a.begin(t, AdminOperation{Kind: "test-factor", TargetID: a.factors[1]})
	must(t, s.ActivateAdminRenewal(ctx, candidate, a.trust, id))
	must(t, s.ActivateAdminRenewal(ctx, candidate, a.trust, id))
	if _, err = tlsHandshake(t, s, a.trust, a.identity, false); err == nil {
		t.Fatal("retired administrator leaf authenticated")
	}
	if _, err = s.BeginAdminOperation(ctx, a.conn, a.trust, a.verifier, a.invitation()); err == nil {
		t.Fatal("existing old TLS connection retained administrator authority")
	}
	current, err := tlsHandshake(t, s, a.trust, identity, false)
	must(t, err)
	if _, err = s.BeginInitialFactor(ctx, current, a.trust, a.verifier); err == nil {
		t.Fatal("renewal reopened bootstrap")
	}
	if _, err = s.FinishAdminOperation(ctx, current, a.trust, a.verifier, stale.ID, a.assertion(t, a.keys[1], stale)); err == nil {
		t.Fatal("old certificate approval survived activation")
	}
	var bootstrap, ceremonies int
	must(t, s.db.QueryRow("SELECT bootstrap_until FROM admin_devices WHERE device_id=?", a.deviceID).Scan(&bootstrap))
	must(t, s.db.QueryRow("SELECT count(*) FROM admin_ceremonies WHERE device_id=?", a.deviceID).Scan(&ceremonies))
	if bootstrap != 0 || ceremonies != 0 {
		t.Fatal("activation retained bootstrap or approvals")
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestAdministratorRenewalRejectsExpandedScopeAndMissingFactors(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	if _, err := s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, NewID(), a.renewalSpec(t)); err == nil {
		t.Fatal("factorless renewal")
	}
	a.setupFactors(t)
	for _, scenario := range []string{"key", "oversized", "malformed", "shorter", "fraction", "device-expiry", "issuer", "ordinary", "id"} {
		t.Run(scenario, func(t *testing.T) {
			spec, trust, id := a.renewalSpec(t), a.trust, NewID()
			switch scenario {
			case "key":
				spec.CSR = csrFor(t, newKey(t))
			case "oversized":
				spec.CSR = make([]byte, pki.MaxCSR+1)
			case "malformed":
				spec.CSR[0] ^= 1
			case "shorter":
				spec.NotAfter = s.now().Add(time.Minute)
			case "fraction":
				spec.NotAfter = spec.NotAfter.Add(time.Nanosecond)
			case "device-expiry":
				spec.NotAfter = s.now().Add(3 * time.Hour)
			case "issuer":
				spec.NotAfter = s.now().Add(5 * time.Hour)
			case "ordinary":
				trust = a.f.trust
			case "id":
				id = "invalid"
			}
			if _, err := s.BeginAdminRenewal(ctx, a.conn, trust, a.verifier, id, spec); err == nil {
				t.Fatal("expanded or malformed renewal accepted")
			}
		})
	}
	c, err := s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, NewID(), a.renewalSpec(t))
	must(t, err)
	response := a.assertion(t, a.keys[0], c)
	_, err = s.db.Exec("UPDATE admin_factors SET tested=0 WHERE id=?", a.factors[1])
	must(t, err)
	if _, err = s.FinishAdminRenewal(ctx, a.conn, a.trust, a.verifier, c.ID, response); err == nil {
		t.Fatal("renewal did not recheck the backup factor at commit")
	}
	_, err = s.db.Exec("UPDATE admin_factors SET tested=1 WHERE id=?", a.factors[1])
	must(t, err)
	if _, err = s.FinishAdminRenewal(ctx, a.conn, a.trust, a.verifier, c.ID, response); err == nil {
		t.Fatal("restoring a factor revived an approval from an older policy revision")
	}
	a.approveRenewal(t)
	if _, err = s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, NewID(), a.renewalSpec(t)); err == nil {
		t.Fatal("second outstanding administrator renewal")
	}
}

func TestAdministratorRenewalAmbiguousIssuanceSurvivesRestartWithoutRetry(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	id := a.approveRenewal(t)
	var request IssuanceRequest
	var der []byte
	calls := 0
	provider := issueFunc(func(_ context.Context, r IssuanceRequest) ([]byte, error) {
		calls++
		request = r
		der = a.signRenewal(t, r)
		return nil, errors.New("synthetic provider failure containing private diagnostic")
	})
	if err := s.IssueAdminRenewal(ctx, a.userID, id, a.trust, provider); err != ErrDenied {
		t.Fatal("ambiguous provider error leaked or succeeded")
	}
	must(t, s.Close())
	reopened, err := Open(ctx, a.f.f.dir)
	must(t, err)
	defer reopened.Close()
	a.f.f.s = reopened
	s = reopened
	if err = s.IssueAdminRenewal(ctx, a.userID, id, a.trust, provider); err == nil || calls != 1 {
		t.Fatal("restart retried an uncertain issuance")
	}
	changed := request
	changed.NotAfter = changed.NotAfter.Add(time.Second)
	if err = s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, a.signRenewal(t, changed)); err == nil {
		t.Fatal("different certificate lifetime reconciled")
	}
	changed = request
	changed.CSR = csrFor(t, newKey(t))
	if err = s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, a.signRenewal(t, changed)); err == nil {
		t.Fatal("different key reconciled")
	}
	must(t, s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, der))
	must(t, s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, der))
	if err = s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, a.signRenewal(t, request)); err == nil {
		t.Fatal("a second signed result replaced the reconciled certificate")
	}
	identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.identity.PrivateKey}
	conn, err := tlsHandshake(t, s, a.trust, identity, true)
	must(t, err)
	must(t, s.ActivateAdminRenewal(ctx, conn, a.trust, id))
	must(t, verifyAudit(ctx, s.db))
}

func TestAdministratorRenewalRechecksAuthorityAndRollsBackAuditFailure(t *testing.T) {
	for _, scenario := range []string{"user", "device", "factor", "expiry", "rollback", "revoked", "approval-audit", "issuing-audit", "activation-audit"} {
		t.Run(scenario, func(t *testing.T) {
			a := adminSeed(t)
			a.setupFactors(t)
			s := a.f.f.s
			if scenario == "approval-audit" {
				c, err := s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, NewID(), a.renewalSpec(t))
				must(t, err)
				_, err = s.db.Exec("CREATE TRIGGER reject_renewal BEFORE INSERT ON audit_events WHEN NEW.action='admin.renewal.approve' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
				must(t, err)
				if _, err = s.FinishAdminRenewal(ctx, a.conn, a.trust, a.verifier, c.ID, a.assertion(t, a.keys[0], c)); err == nil {
					t.Fatal("approval ignored audit failure")
				}
				var count int
				must(t, s.db.QueryRow("SELECT count(*) FROM admin_renewals").Scan(&count))
				if count != 0 {
					t.Fatal("unaudited reservation committed")
				}
				return
			}
			id := a.approveRenewal(t)
			if scenario == "activation-audit" {
				identity := a.issueRenewal(t, id)
				conn, err := tlsHandshake(t, s, a.trust, identity, true)
				must(t, err)
				_, err = s.db.Exec("CREATE TRIGGER reject_renewal BEFORE INSERT ON audit_events WHEN NEW.action='admin.renewal.activate' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
				must(t, err)
				if err = s.ActivateAdminRenewal(ctx, conn, a.trust, id); err == nil {
					t.Fatal("activation ignored audit failure")
				}
				_, err = tlsHandshake(t, s, a.trust, a.identity, false)
				must(t, err)
				if _, err = tlsHandshake(t, s, a.trust, identity, false); err == nil {
					t.Fatal("failed activation changed the live certificate")
				}
				return
			}
			switch scenario {
			case "user", "device":
				target := a.userID
				if scenario == "device" {
					target = a.deviceID
				}
				must(t, s.Update(ctx, a.userID, func(tx *Tx) error { return tx.Disable(scenario, target) }))
			case "factor":
				_, err := s.db.Exec("UPDATE admin_factors SET enabled=0 WHERE id=?", a.factors[1])
				must(t, err)
			case "expiry", "rollback":
				now := s.now()
				delta := 10 * time.Minute
				if scenario == "rollback" {
					delta = -time.Second
				}
				s.now = func() time.Time { return now.Add(delta) }
			case "revoked":
				must(t, s.Update(ctx, a.userID, func(tx *Tx) error { return tx.RevokeAdminRenewal(id) }))
			case "issuing-audit":
				_, err := s.db.Exec("CREATE TRIGGER reject_renewal BEFORE INSERT ON audit_events WHEN NEW.action='admin.renewal.issuing' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
				must(t, err)
			}
			calls := 0
			if err := s.IssueAdminRenewal(ctx, a.userID, id, a.trust, issueFunc(func(context.Context, IssuanceRequest) ([]byte, error) { calls++; return nil, nil })); err == nil || calls != 0 {
				t.Fatal("denied or unaudited issuance reached the provider")
			}
		})
	}
}

func TestAdministratorRenewalSnapshotRevokesPendingAuthority(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	id := a.approveRenewal(t)
	identity := a.issueRenewal(t, id)
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.sqlite")
	must(t, a.f.f.s.Snapshot(ctx, path))
	db, err := sql.Open("sqlite", databaseURI(path))
	must(t, err)
	defer db.Close()
	var state string
	var candidate []byte
	must(t, db.QueryRow("SELECT state,certificate_der FROM admin_renewals WHERE id=?", id).Scan(&state, &candidate))
	if state != "revoked" || !bytes.Equal(candidate, identity.Certificate[0]) {
		t.Fatal("snapshot retained renewal authority or lost public evidence")
	}
	_, err = tlsHandshake(t, a.f.f.s, a.trust, identity, true)
	must(t, err)
	must(t, verifyAudit(ctx, db))
	var checkpoint Checkpoint
	must(t, db.QueryRow("SELECT audit_sequence,audit_hash FROM meta WHERE singleton=1").Scan(&checkpoint.Sequence, &checkpoint.Hash))
	must(t, validateRecovery(ctx, path, checkpoint))
	_, err = db.Exec("UPDATE admin_renewals SET state='issued' WHERE id=?", id)
	must(t, err)
	if err = validateRecovery(ctx, path, checkpoint); err != ErrQuarantine {
		t.Fatal("restore validation accepted a snapshot with renewed authority")
	}
}

func TestAdministratorRenewalRechecksIssuedCandidateOnExistingTLS(t *testing.T) {
	for _, scenario := range []string{"user", "device", "factor", "policy", "expiry", "revoke"} {
		t.Run(scenario, func(t *testing.T) {
			a := adminSeed(t)
			a.setupFactors(t)
			s := a.f.f.s
			id := a.approveRenewal(t)
			identity := a.issueRenewal(t, id)
			candidate, err := tlsHandshake(t, s, a.trust, identity, true)
			must(t, err)
			switch scenario {
			case "user", "device":
				target := a.userID
				if scenario == "device" {
					target = a.deviceID
				}
				must(t, s.Update(ctx, a.userID, func(tx *Tx) error { return tx.Disable(scenario, target) }))
			case "factor":
				_, err = s.db.Exec("UPDATE admin_factors SET enabled=0 WHERE id=?", a.factors[1])
				must(t, err)
			case "policy":
				// Even a restored value belongs to a later approval revision.
				_, err = s.db.Exec("UPDATE admin_factors SET tested=0 WHERE id=?; UPDATE admin_factors SET tested=1 WHERE id=?", a.factors[1], a.factors[1])
				must(t, err)
			case "expiry":
				now := s.now()
				s.now = func() time.Time { return now.Add(10 * time.Minute) }
			case "revoke":
				must(t, s.Update(ctx, a.userID, func(tx *Tx) error { return tx.RevokeAdminRenewal(id) }))
			}
			if err = s.ActivateAdminRenewal(ctx, candidate, a.trust, id); err == nil {
				t.Fatal("previously authenticated candidate bypassed current authority")
			}
			if _, err = tlsHandshake(t, s, a.trust, identity, true); err == nil {
				t.Fatal("invalidated candidate authenticated again")
			}
			if err = s.ReconcileAdminRenewal(ctx, a.userID, id, a.trust, identity.Certificate[0]); err == nil {
				t.Fatal("public result reconciliation revived stale authority")
			}
		})
	}
}

func TestVersionFiveRenewalMigrationPreservesIdentityAndRollsBackFailure(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrate", true: "rollback"}[reject], func(t *testing.T) {
			a := adminSeed(t)
			a.setupFactors(t)
			a.begin(t, a.invitation())
			s := a.f.f.s
			_, err := s.db.Exec("DROP TABLE admin_renewals; PRAGMA user_version=5")
			must(t, err)
			hash := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema + policySchema + closureSchema))
			old := hex.EncodeToString(hash[:])
			_, err = s.db.Exec("UPDATE meta SET schema_digest=?", old)
			must(t, err)
			if reject {
				_, err = s.db.Exec("CREATE TRIGGER reject_renewal_migration BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
				must(t, err)
			}
			must(t, s.Close())
			reopened, err := Open(ctx, a.f.f.dir)
			if reject {
				if err == nil {
					_ = reopened.Close()
					t.Fatal("migration ignored failed audit")
				}
				db, err := sql.Open("sqlite", databaseURI(filepath.Join(a.f.f.dir, "controller.sqlite")))
				must(t, err)
				defer db.Close()
				var version, tables, ceremonies int
				var digest string
				must(t, db.QueryRow("PRAGMA user_version").Scan(&version))
				must(t, db.QueryRow("SELECT schema_digest FROM meta").Scan(&digest))
				must(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='admin_renewals'").Scan(&tables))
				must(t, db.QueryRow("SELECT count(*) FROM admin_ceremonies").Scan(&ceremonies))
				if version != 5 || digest != old || tables != 0 || ceremonies == 0 {
					t.Fatal("partial migration escaped rollback")
				}
				return
			}
			must(t, err)
			defer reopened.Close()
			var version, factors, ceremonies int
			var leaf []byte
			must(t, reopened.db.QueryRow("PRAGMA user_version").Scan(&version))
			must(t, reopened.db.QueryRow("SELECT count(*) FROM admin_factors WHERE enabled=1 AND tested=1").Scan(&factors))
			must(t, reopened.db.QueryRow("SELECT count(*) FROM admin_ceremonies").Scan(&ceremonies))
			must(t, reopened.db.QueryRow("SELECT certificate_der FROM admin_devices WHERE device_id=?", a.deviceID).Scan(&leaf))
			if version != 6 || factors != 2 || ceremonies != 0 || !bytes.Equal(leaf, a.identity.Certificate[0]) {
				t.Fatal("migration changed live identity or retained approvals")
			}
			must(t, verifyAudit(ctx, reopened.db))
		})
	}
}

// A CSR with identity claims must not become a renewal request, even when it is
// signed with the current key. Empty claims are enforced by the existing parser.
func TestAdministratorRenewalRejectsCSRClaims(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	spec := a.renewalSpec(t)
	key := a.identity.PrivateKey.(*ecdsa.PrivateKey)
	var err error
	spec.CSR, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"admin.portico.test"}}, key)
	must(t, err)
	if _, err = a.f.f.s.BeginAdminRenewal(ctx, a.conn, a.trust, a.verifier, NewID(), spec); err == nil {
		t.Fatal("CSR claims accepted")
	}
}
