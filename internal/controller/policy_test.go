package controller

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"sync"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type policyFixture struct {
	device, connector                 *enrollmentFixture
	engine                            *PolicyEngine
	deviceConn, connectorConn         *tls.Conn
	deviceLeaf, connectorLeaf         []byte
	deviceIdentity, connectorIdentity tls.Certificate
}

func enrolledPolicyPeer(t *testing.T, f *enrollmentFixture, principal string) (*tls.Conn, []byte, tls.Certificate) {
	t.Helper()
	s := f.f.s
	now := s.now()
	id, attempt := NewID(), NewID()
	secret, e := s.Invite(ctx, f.f.actor, InvitationSpec{ID: id, IssuerID: f.trust.IssuerID(), PrincipalID: principal, Profile: f.trust.Profile(), ExpiresAt: now.Add(10 * time.Minute), NotAfter: now.Add(time.Hour)})
	must(t, e)
	key := newKey(t)
	csr := csrFor(t, key)
	must(t, s.ReserveEnrollment(ctx, f.f.actor, id, secret, attempt, csr))
	must(t, s.IssueEnrollment(ctx, f.f.actor, id, f.trust, f.provider(t)))
	der, e := s.EnrollmentCertificate(ctx, f.f.actor, id, secret, attempt, csr)
	must(t, e)
	identity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	c, e := tlsHandshake(t, s, f.trust, identity, true)
	must(t, e)
	must(t, s.ActivateEnrollment(ctx, id, c, f.trust))
	return c, der, identity
}
func connectorPolicyFixture(t *testing.T, device *enrollmentFixture) *enrollmentFixture {
	t.Helper()
	root, rk := testfixture.Root(t)
	ik := newKey(t)
	ca := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated policy connector issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	cfg := pki.Config{DeploymentID: device.config.DeploymentID, IssuerID: NewID(), Profile: pki.Connector, RootDER: root.Raw, IssuerDER: ca.Raw}
	trust, e := pki.NewTrust(cfg)
	must(t, e)
	must(t, device.f.s.Update(ctx, device.f.actor, func(tx *Tx) error { return tx.BindIssuer(trust) }))
	return &enrollmentFixture{f: device.f, trust: trust, config: cfg, ca: ca, caKey: ik}
}
func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	d := enrollmentSeed(t)
	return policyFixtureFor(t, d)
}
func policyFixtureFor(t *testing.T, d *enrollmentFixture) *policyFixture {
	t.Helper()
	c := connectorPolicyFixture(t, d)
	v := &policyFixture{device: d, connector: c}
	v.deviceConn, v.deviceLeaf, v.deviceIdentity = enrolledPolicyPeer(t, d, d.f.device.ID)
	v.connectorConn, v.connectorLeaf, v.connectorIdentity = enrolledPolicyPeer(t, c, c.f.connector.ID)
	var e error
	v.engine, e = NewPolicyEngine(d.f.s, PolicyConfig{DeviceTrust: d.trust, ConnectorTrust: c.trust, ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}, MaxSessions: 16, MaxDeviceSessions: 4, MaxConnectorSessions: 8, SessionLifetime: time.Hour, LeaseLifetime: 2 * time.Second, ActivationLifetime: time.Second})
	must(t, e)
	return v
}
func (v *policyFixture) request() AuthorizeRequest {
	return AuthorizeRequest{Version: 1, ClientLeafDER: v.deviceLeaf, ResourceID: v.device.f.resource.ID, Revision: 1}
}

func TestPolicyAuthorizeActivateRenewAndReplay(t *testing.T) {
	v := newPolicyFixture(t)
	s := v.device.f.s
	list, e := v.engine.Catalog(ctx, v.deviceConn)
	must(t, e)
	if len(list) != 1 || list[0].ID != v.device.f.resource.ID {
		t.Fatal("catalog missing exact grant")
	}
	a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	if a.Resource.Address != v.device.f.resource.Address || a.Resource.Port != 8096 || a.Resource.Protocol != "tcp" || a.Sequence != 1 || a.SessionUntil != v.device.f.grant.Until || a.LeaseUntil.Sub(a.IssuedAt) != 2*time.Second {
		t.Fatal("authorization widened destination or expiry")
	}
	r := SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: 1}
	if _, e = v.engine.Renew(ctx, v.connectorConn, r); e == nil {
		t.Fatal("renewed before activation")
	}
	active, e := v.engine.Activate(ctx, v.connectorConn, r)
	must(t, e)
	if _, e = v.engine.Activate(ctx, v.connectorConn, r); e == nil {
		t.Fatal("replayed activation")
	}
	r.Sequence = active.Sequence
	renew, e := v.engine.Renew(ctx, v.connectorConn, r)
	must(t, e)
	if renew.SessionUntil != a.SessionUntil || renew.Sequence != active.Sequence+1 {
		t.Fatal("renewal extended absolute lifetime")
	}
	if _, e = v.engine.Renew(ctx, v.connectorConn, r); e == nil {
		t.Fatal("replayed renewal")
	}
	must(t, v.engine.CloseSession(ctx, v.connectorConn, r))
	r.Sequence = renew.Sequence
	if _, e = v.engine.Renew(ctx, v.connectorConn, r); e == nil {
		t.Fatal("closed session revived")
	}
	var count int
	must(t, s.db.QueryRow("SELECT count(*) FROM session_cancellations WHERE session_id=?", a.SessionID).Scan(&count))
	if count != 1 {
		t.Fatal("missing durable cancellation")
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestPolicyEveryLiveAuthorityGate(t *testing.T) {
	for _, kind := range []string{"user", "device", "connector", "issuer", "resource", "grant", "host_binding", "certificate", "connector_certificate", "management", "protected", "ambiguous_grant", "ambiguous_host", "revision", "protocol", "wrong_resource", "nil_transport", "client_as_connector", "future_grant", "grant_expired", "deadline", "clock_rollback", "audit_failure", "emergency"} {
		t.Run(kind, func(t *testing.T) {
			v := newPolicyFixture(t)
			f := v.device.f
			r := v.request()
			conn := v.connectorConn
			var clientID, connectorID string
			must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(v.deviceLeaf)).Scan(&clientID))
			must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(v.connectorLeaf)).Scan(&connectorID))
			ids := map[string]string{"user": f.user.ID, "device": f.device.ID, "connector": f.connector.ID, "issuer": v.device.trust.IssuerID(), "resource": f.resource.ID, "grant": f.grant.ID, "host_binding": f.host.ID, "certificate": clientID}
			if id, ok := ids[kind]; ok {
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable(kind, id) }))
			} else {
				switch kind {
				case "connector_certificate":
					must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("certificate", connectorID) }))
				case "management", "protected":
					res := f.resource
					res.Revision = 2
					if kind == "management" {
						res.Kind = "management"
					} else {
						res.Address = "10.99.0.1"
					}
					must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
						if e := tx.ReviseResource(1, res); e != nil {
							return e
						}
						g := f.grant
						g.ID = NewID()
						g.Revision = 2
						if e := tx.AddGrant(g); e != nil {
							return e
						}
						h := f.host
						h.ID = NewID()
						h.Revision = 2
						return tx.AddHostBinding(h)
					}))
					r.Revision = 2
				case "ambiguous_grant":
					g := f.grant
					g.ID = NewID()
					must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddGrant(g) }))
				case "ambiguous_host":
					h := f.host
					h.ID = NewID()
					must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddHostBinding(h) }))
				case "revision":
					r.Revision = 2
				case "protocol":
					r.Version = 2
				case "wrong_resource":
					r.ResourceID = NewID()
				case "nil_transport":
					conn = nil
				case "client_as_connector":
					conn = v.deviceConn
				case "future_grant":
					_, e := f.s.db.Exec("UPDATE grants SET valid_from=? WHERE id=?", f.s.now().Add(time.Minute).UnixNano(), f.grant.ID)
					must(t, e)
				case "grant_expired":
					now := f.grant.Until
					f.s.now = func() time.Time { return now }
				case "deadline":
					now := f.s.now().Add(time.Hour)
					f.s.now = func() time.Time { return now }
				case "clock_rollback":
					now := f.s.now().Add(-time.Second)
					f.s.now = func() time.Time { return now }
				case "audit_failure":
					_, e := f.s.db.Exec("CREATE TRIGGER policy_reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
					must(t, e)
				case "emergency":
					f.s.EmergencyDeny()
				}
			}
			before := summary(t, f.s)
			a, e := v.engine.Authorize(ctx, conn, r)
			if e == nil || a.SessionID != "" {
				t.Fatal("denied gate issued permission")
			}
			if summary(t, f.s) != before {
				t.Fatal("denied permission committed state/audit")
			}
		})
	}
}

func TestPolicyActivationExpiryRevocationAndQuotaRace(t *testing.T) {
	for _, kind := range []string{"expired_activation", "expired_lease", "revoked", "changed_endpoint", "restarted", "changed_config"} {
		t.Run(kind, func(t *testing.T) {
			v := newPolicyFixture(t)
			s := v.device.f.s
			a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
			must(t, e)
			switch kind {
			case "expired_activation":
				s.now = func() time.Time { return a.ActivateUntil }
			case "expired_lease":
				s.now = func() time.Time { return a.LeaseUntil }
			case "revoked":
				must(t, s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.Disable("grant", v.device.f.grant.ID) }))
			case "changed_endpoint":
				r := v.device.f.resource
				r.Revision = 2
				r.Port = 22
				must(t, s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.ReviseResource(1, r) }))
			case "restarted":
				must(t, s.Close())
				reopened, e := Open(ctx, v.device.f.dir)
				must(t, e)
				t.Cleanup(func() { _ = reopened.Close() })
				v.engine.store = reopened
			case "changed_config":
				cfg := v.engine.config
				cfg.LeaseLifetime = time.Second
				v.engine, e = NewPolicyEngine(s, cfg)
				must(t, e)
			}
			if _, e := v.engine.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: 1}); e == nil {
				t.Fatal("invalid session activated")
			}
		})
	}
	v := newPolicyFixture(t)
	cfg := v.engine.config
	cfg.MaxDeviceSessions = 1
	var e error
	v.engine, e = NewPolicyEngine(v.device.f.s, cfg)
	must(t, e)
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
			results <- e == nil
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("quota race admitted %d", n)
	}
}

func TestPolicyDeviceIsolationAndWrongConnector(t *testing.T) {
	v := newPolicyFixture(t)
	f := v.device.f
	d := Device{ID: NewID(), UserID: f.user.ID, Name: "New device", Platform: "linux", Enabled: true, NotAfter: f.device.NotAfter}
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddDevice(d) }))
	conn, leaf, _ := enrolledPolicyPeer(t, v.device, d.ID)
	list, e := v.engine.Catalog(ctx, conn)
	must(t, e)
	if len(list) != 0 {
		t.Fatal("new device inherited grants")
	}
	r := v.request()
	r.ClientLeafDER = leaf
	if _, e = v.engine.Authorize(ctx, v.connectorConn, r); e == nil {
		t.Fatal("other device used grant")
	}
	k := Connector{ID: NewID(), Name: "Other connector", Version: "0.4.0-dev", Enabled: true}
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddConnector(k) }))
	other, _, _ := enrolledPolicyPeer(t, v.connector, k.ID)
	if _, e = v.engine.Authorize(ctx, other, v.request()); e == nil {
		t.Fatal("connector hosted another connector's resource")
	}
	a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	if _, e = v.engine.Activate(ctx, other, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: 1}); e == nil {
		t.Fatal("session ID acted as bearer authority")
	}
}
