package controller

import (
	"crypto/tls"
	"testing"
	"time"
)

func active(t *testing.T, f *enrollmentFixture) (invited, *tls.Conn) {
	t.Helper()
	v := f.issue(t)
	conn, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v.invited), true)
	must(t, e)
	must(t, f.f.s.ActivateEnrollment(ctx, v.id, conn, f.trust))
	return v.invited, conn
}

func TestOrdinaryRenewalProvesKeyAndPreservesAuthority(t *testing.T) {
	f := enrollmentSeed(t)
	v, conn := active(t, f)
	until := f.f.s.now().Add(90 * time.Minute)
	if secret, e := f.f.s.ReserveRenewal(ctx, NewID(), conn, f.trust, csrFor(t, newKey(t)), until); e == nil || secret != "" {
		t.Fatal("renewal changed key without approval")
	}
	if secret, e := f.f.s.ReserveRenewal(ctx, NewID(), conn, f.trust, v.csr, f.f.s.now().Add(3*time.Hour)); e == nil || secret != "" {
		t.Fatal("renewal extended enrollment authority")
	}
	id := NewID()
	secret, e := f.f.s.ReserveRenewal(ctx, id, conn, f.trust, v.csr, until)
	must(t, e)
	if _, e = f.f.s.ReserveRenewal(ctx, NewID(), conn, f.trust, v.csr, until); e == nil {
		t.Fatal("parallel renewal reservation")
	}
	must(t, f.f.s.IssueEnrollment(ctx, f.f.actor, id, f.trust, f.provider(t)))
	der, e := f.f.s.EnrollmentCertificate(ctx, f.f.actor, id, secret, id, v.csr)
	must(t, e)
	if _, e = f.f.s.Authenticate(ctx, conn, f.trust); e != nil {
		t.Fatal("old key closed before new proof")
	}
	renewed := v
	renewed.der = der
	next, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(renewed), true)
	must(t, e)
	must(t, f.f.s.ActivateEnrollment(ctx, id, next, f.trust))
	identity, e := f.f.s.Authenticate(ctx, next, f.trust)
	must(t, e)
	if identity.PrincipalID != f.f.device.ID || !identity.NotAfter.Equal(until) {
		t.Fatal("renewal identity/deadline changed")
	}
	if _, e = f.f.s.Authenticate(ctx, conn, f.trust); e == nil {
		t.Fatal("old certificate survived activation")
	}
	if _, e = tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v), false); e == nil {
		t.Fatal("old certificate handshook after renewal")
	}
	var deviceEnd int64
	must(t, f.f.s.db.QueryRow("SELECT not_after FROM devices WHERE id=?", f.f.device.ID).Scan(&deviceEnd))
	if deviceEnd != f.f.device.NotAfter.UnixNano() {
		t.Fatal("device authority extended")
	}
}

func TestRenewalRevocationBeforeActivation(t *testing.T) {
	f := enrollmentSeed(t)
	v, conn := active(t, f)
	id := NewID()
	secret, e := f.f.s.ReserveRenewal(ctx, id, conn, f.trust, v.csr, f.f.s.now().Add(90*time.Minute))
	must(t, e)
	must(t, f.f.s.IssueEnrollment(ctx, f.f.actor, id, f.trust, f.provider(t)))
	der, e := f.f.s.EnrollmentCertificate(ctx, f.f.actor, id, secret, id, v.csr)
	must(t, e)
	renewed := v
	renewed.der = der
	next, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(renewed), true)
	must(t, e)
	must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(v.id) }))
	if e = f.f.s.ActivateEnrollment(ctx, id, next, f.trust); e == nil {
		t.Fatal("revoked source activated its pending renewal")
	}
	if _, e = tlsHandshake(t, f.f.s, f.trust, tlsIdentity(renewed), true); e == nil {
		t.Fatal("revoked source's renewal handshook")
	}
}

func TestTLSExpiryIssuerAndStorageDenials(t *testing.T) {
	for _, kind := range []string{"issuer", "user", "leaf", "expiry", "storage", "emergency", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := enrollmentSeed(t)
			v, conn := active(t, f)
			switch kind {
			case "issuer":
				must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.Disable("issuer", f.trust.IssuerID()) }))
			case "user":
				must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.Disable("user", f.f.user.ID) }))
			case "leaf":
				must(t, f.f.s.Update(ctx, f.f.actor, func(tx *Tx) error { return tx.RevokeEnrollment(v.id) }))
			case "expiry":
				now := f.f.s.now()
				f.f.s.now = func() time.Time { return now.Add(time.Hour) }
			case "storage":
				must(t, f.f.s.Close())
			case "emergency":
				f.f.s.EmergencyDeny()
			case "rollback":
				now := f.f.s.now()
				f.f.s.now = func() time.Time { return now.Add(-time.Hour) }
			}
			if _, e := f.f.s.Authenticate(ctx, conn, f.trust); e == nil {
				t.Fatal("stale authenticated identity survived denial")
			}
			if _, e := tlsHandshake(t, f.f.s, f.trust, tlsIdentity(v), false); e == nil {
				t.Fatal("TLS accepted inactive authority")
			}
		})
	}
}
