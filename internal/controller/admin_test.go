package controller

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type adminFixture struct {
	f        *enrollmentFixture
	trust    *pki.Trust
	conn     *tls.Conn
	identity tls.Certificate
	verifier *adminauth.Verifier
	keys     []*testfixture.VirtualKey
	factors  []string
}

func adminSeed(t *testing.T) *adminFixture {
	t.Helper()
	f := enrollmentSeed(t)
	root, rk := testfixture.Root(t)
	ik := newKey(t)
	ca := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated administrator issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}, root, &ik.PublicKey, rk)
	trust, e := pki.NewTrust(pki.Config{DeploymentID: f.config.DeploymentID, IssuerID: NewID(), Profile: pki.Administrator, RootDER: root.Raw, IssuerDER: ca.Raw})
	must(t, e)
	key := newKey(t)
	u, e := pki.IdentityURI(f.config.DeploymentID, pki.Administrator, f.f.device.ID)
	must(t, e)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: f.f.s.now().Add(-time.Minute), NotAfter: f.f.s.now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, ca, &key.PublicKey, ik)
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RegisterAdminDevice(f.f.user.ID, f.f.device.ID, trust, leaf.Raw) }))
	conn, e := tlsHandshake(t, f.f.s, trust, tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}, false)
	must(t, e)
	keys := []*testfixture.VirtualKey{testfixture.Virtual(t), testfixture.Virtual(t), testfixture.Virtual(t)}
	models := []adminauth.Model{}
	for _, k := range keys {
		models = append(models, adminauth.Model{AAGUID: k.AAGUID.String(), RootsDER: [][]byte{k.Root.Raw}})
	}
	v, e := adminauth.New(adminauth.Config{Origin: "https://admin.portico.test", Models: models, ValidUntil: time.Now().Add(time.Hour)})
	must(t, e)
	return &adminFixture{f: f, trust: trust, conn: conn, identity: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}, verifier: v, keys: keys}
}
func (a *adminFixture) register(t *testing.T, key *testfixture.VirtualKey, challenge AdminChallenge) string {
	t.Helper()
	response := key.Register(t, base64.RawURLEncoding.EncodeToString(challenge.Registration.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
	_, e := a.f.f.s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, response)
	must(t, e)
	var id string
	must(t, a.f.f.s.db.QueryRow("SELECT id FROM admin_factors WHERE credential_id=?", key.ID).Scan(&id))
	return id
}
func (a *adminFixture) begin(t *testing.T, op AdminOperation) AdminChallenge {
	t.Helper()
	c, e := a.f.f.s.BeginAdminOperation(ctx, a.conn, a.trust, a.verifier, op)
	must(t, e)
	return c
}
func (a *adminFixture) assertion(t *testing.T, key *testfixture.VirtualKey, c AdminChallenge) []byte {
	t.Helper()
	return key.Assert(t, base64.RawURLEncoding.EncodeToString(c.Approval.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
}
func (a *adminFixture) verifyKey(t *testing.T, key *testfixture.VirtualKey, id string) {
	t.Helper()
	c := a.begin(t, AdminOperation{Kind: "test-factor", TargetID: id})
	_, e := a.f.f.s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, a.assertion(t, key, c))
	must(t, e)
}
func (a *adminFixture) setupFactors(t *testing.T) {
	t.Helper()
	for _, key := range a.keys[:2] {
		c, e := a.f.f.s.BeginInitialFactor(ctx, a.conn, a.trust, a.verifier)
		must(t, e)
		id := a.register(t, key, c)
		a.factors = append(a.factors, id)
		a.verifyKey(t, key, id)
	}
}
func (a *adminFixture) invitation() AdminOperation {
	f := a.f.f
	spec := &InvitationSpec{ID: NewID(), IssuerID: a.f.trust.IssuerID(), PrincipalID: f.device.ID, Profile: pki.Device, ExpiresAt: f.s.now().Add(5 * time.Minute), NotAfter: f.s.now().Add(time.Hour)}
	return AdminOperation{Kind: "invite", TargetID: spec.ID, Invitation: spec}
}

func TestAdminTLSBoundAtomicInvitationAndBackupKeyRecovery(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	if _, e := s.BeginAdminOperation(ctx, a.conn, a.trust, a.verifier, a.invitation()); e == nil {
		t.Fatal("factorless invitation")
	}
	a.setupFactors(t)
	if _, e := s.BeginInitialFactor(ctx, a.conn, a.trust, a.verifier); e == nil {
		t.Fatal("bootstrap allowed a third factor")
	}
	op := a.invitation()
	challenge := a.begin(t, op)
	op.Invitation.PrincipalID = NewID()
	response := a.assertion(t, a.keys[0], challenge)
	var wg sync.WaitGroup
	results := make(chan AdminResult, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, response)
			results <- r
			errs <- e
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	successes := 0
	for e := range errs {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("approval consumed more or less than once")
	}
	secrets := 0
	for r := range results {
		if r.InvitationSecret != "" {
			secrets++
		}
	}
	if secrets != 1 {
		t.Fatal("secret escaped failed transaction")
	}
	var principal string
	must(t, s.db.QueryRow("SELECT device_id FROM enrollments WHERE id=?", op.TargetID).Scan(&principal))
	if principal != a.f.f.device.ID {
		t.Fatal("caller changed stored operation")
	}
	// The independently registered backup factor retires the primary. The
	// primary cannot approve its own retirement or register its replacement.
	challenge = a.begin(t, AdminOperation{Kind: "disable-factor", TargetID: a.factors[0]})
	_, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, a.assertion(t, a.keys[1], challenge))
	must(t, e)
	challenge = a.begin(t, AdminOperation{Kind: "register-factor", TargetID: NewID()})
	if _, e = s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, a.assertion(t, a.keys[0], challenge)); e == nil {
		t.Fatal("retired primary approved replacement")
	}
	result, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, a.assertion(t, a.keys[1], challenge))
	must(t, e)
	id := a.register(t, a.keys[2], *result.Registration)
	a.verifyKey(t, a.keys[2], id)
	challenge = a.begin(t, a.invitation())
	_, e = s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, challenge.ID, a.assertion(t, a.keys[2], challenge))
	must(t, e)
	must(t, verifyAudit(ctx, s.db))
}

func TestAdminStaleApprovalAuditRollbackAndDeviceRevocation(t *testing.T) {
	a := adminSeed(t)
	a.setupFactors(t)
	s := a.f.f.s
	op := a.invitation()
	c := a.begin(t, op)
	response := a.assertion(t, a.keys[0], c)
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Changed policy", true}) }))
	if _, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
		t.Fatal("stale policy approved")
	}
	op = a.invitation()
	c = a.begin(t, op)
	response = a.assertion(t, a.keys[0], c)
	_, e := s.db.Exec("CREATE TRIGGER reject_admin_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
	must(t, e)
	result, e := s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response)
	if e == nil || result.InvitationSecret != "" {
		t.Fatal("unaudited invitation escaped")
	}
	var state string
	must(t, s.db.QueryRow("SELECT state FROM admin_ceremonies WHERE id=?", c.ID).Scan(&state))
	if state != "pending" {
		t.Fatal("partial approval commit")
	}
	_, e = s.db.Exec("DROP TRIGGER reject_admin_audit")
	must(t, e)
	_, e = s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response)
	must(t, e)
	op = a.invitation()
	c = a.begin(t, op)
	response = a.assertion(t, a.keys[1], c)
	must(t, s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", a.f.f.device.ID) }))
	if _, e = s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
		t.Fatal("disabled device retained admin authority")
	}
}

func TestAdministratorProfileCannotEnterOrdinaryRegistry(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	if e := s.Update(ctx, a.f.f.actor, func(tx *Tx) error { return tx.BindIssuer(a.trust) }); e == nil {
		t.Fatal("administrator issuer entered ordinary registry")
	}
	ordinary := a.f.issue(t)
	if _, e := tlsHandshake(t, s, a.trust, tlsIdentity(ordinary.invited), false); e == nil {
		t.Fatal("ordinary credential crossed administrator boundary")
	}
}

func TestBootstrapFactorCompletionRechecksWindow(t *testing.T) {
	a := adminSeed(t)
	s := a.f.f.s
	c, e := s.BeginInitialFactor(ctx, a.conn, a.trust, a.verifier)
	must(t, e)
	response := a.keys[0].Register(t, base64.RawURLEncoding.EncodeToString(c.Registration.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
	// Move the local bootstrap deadline behind now without changing the policy
	// generation, to isolate the finish-time deadline check from stale approvals.
	_, e = s.db.Exec("UPDATE admin_devices SET bootstrap_until=?", s.now().Add(-time.Second).UnixNano())
	must(t, e)
	if _, e = s.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
		t.Fatal("expired bootstrap completed factor registration")
	}
}
