package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"time"

	"portico.local/portico/internal/pki"
)

// BindIssuer is a trusted local configuration operation. It neither provisions
// a CA nor authorizes an administrator. A deployment and profile cannot be
// changed by passing a different public trust configuration later.
func (t *Tx) BindIssuer(trust *pki.Trust) error {
	if e := t.guard(trust != nil && trust.Profile() != pki.Administrator); e != nil {
		return e
	}
	var foreign int
	if e := t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM pki_bindings WHERE deployment_id<>?", trust.DeploymentID()).Scan(&foreign); e != nil {
		return t.fail(ErrStorage)
	}
	if foreign != 0 {
		return t.fail(ErrDenied)
	}
	if e := t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_devices WHERE issuer_sha256=? OR deployment_id<>?", trust.IssuerFingerprint(), trust.DeploymentID()).Scan(&foreign); e != nil || foreign != 0 {
		return t.fail(ErrDenied)
	}
	if e := t.AddIssuer(Issuer{trust.IssuerID(), true, trust.NotAfter()}); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO pki_bindings VALUES(?,?,?,?,?)", trust.IssuerID(), trust.DeploymentID(), string(trust.Profile()), trust.RootFingerprint(), trust.IssuerFingerprint()); e != nil {
		return e
	}
	return t.event("issuer.bind", trust.IssuerID())
}

type InvitationSpec struct {
	ID, IssuerID, PrincipalID string
	Profile                   pki.Profile
	ExpiresAt, NotAfter       time.Time
}

// Invite is a trusted local harness operation, not an administrative API. The
// future API must verify and consume fresh hardware approval before calling it.
// Plaintext is returned only after the transaction and its audit event commit.
// No method recovers plaintext from an invitation ID or its stored hash.
func (s *Store) Invite(ctx context.Context, actor string, v InvitationSpec) (string, error) {
	var secret string
	e := s.Update(ctx, actor, func(t *Tx) error {
		var e error
		secret, e = t.invite(v)
		return e
	})
	if e != nil {
		return "", e
	}
	return secret, nil
}

func (t *Tx) invite(v InvitationSpec) (string, error) {
	var secret string
	e := func() error {
		if e := t.guard(validID(v.ID) && validID(v.IssuerID) && validID(v.PrincipalID) && pki.ValidProfile(v.Profile) && interval(t.now, v.ExpiresAt) && v.ExpiresAt.Sub(t.now) <= time.Hour && interval(t.now, v.NotAfter) && v.NotAfter.Equal(v.NotAfter.Truncate(time.Second))); e != nil {
			return e
		}
		if e := t.enrollmentAuthority(v.IssuerID, v.PrincipalID, v.Profile, v.NotAfter); e != nil {
			return e
		}
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return t.fail(ErrStorage)
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
		var device, connector any
		if v.Profile == pki.Device {
			device = v.PrincipalID
		} else {
			connector = v.PrincipalID
		}
		if e := t.exec(`INSERT INTO enrollments(id,issuer_id,device_id,connector_id,token_hash,created_at,expires_at,not_after,state) VALUES(?,?,?,?,?,?,?,?,'invited')`, v.ID, v.IssuerID, device, connector, pki.Hash(b), t.now.UnixNano(), v.ExpiresAt.UnixNano(), v.NotAfter.UnixNano()); e != nil {
			return e
		}
		return t.event("enrollment.invite", v.ID)
	}()
	if e != nil {
		return "", e
	}
	return secret, nil
}

func (t *Tx) enrollmentAuthority(issuer, principal string, profile pki.Profile, until time.Time) error {
	var issuerEnd int64
	if e := t.tx.QueryRowContext(t.ctx, `SELECT i.not_after FROM issuers i JOIN pki_bindings p ON p.issuer_id=i.id WHERE i.id=? AND i.enabled=1 AND p.profile=?`, issuer, string(profile)).Scan(&issuerEnd); e != nil {
		return t.fail(ErrDenied)
	}
	if !until.After(t.now) || until.UnixNano() > issuerEnd {
		return t.fail(ErrDenied)
	}
	var enabled int
	if profile == pki.Device {
		var end int64
		e := t.tx.QueryRowContext(t.ctx, `SELECT d.enabled*u.enabled,d.not_after FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?`, principal).Scan(&enabled, &end)
		if e != nil || enabled != 1 || until.UnixNano() > end {
			return t.fail(ErrDenied)
		}
	} else if profile == pki.Connector {
		if e := t.tx.QueryRowContext(t.ctx, "SELECT enabled FROM connectors WHERE id=?", principal).Scan(&enabled); e != nil || enabled != 1 {
			return t.fail(ErrDenied)
		}
	} else {
		return t.fail(ErrDenied)
	}
	return nil
}

type enrollment struct {
	id, issuer, principal, tokenHash, state string
	profile                                 pki.Profile
	created, expires, until                 int64
	attempt, spki, certificateID, replaces  sql.NullString
	csr, certificate                        []byte
}

func (t *Tx) enrollment(id string) (enrollment, error) {
	var v enrollment
	e := t.tx.QueryRowContext(t.ctx, `SELECT e.id,e.issuer_id,coalesce(e.device_id,e.connector_id),p.profile,e.token_hash,e.state,e.created_at,e.expires_at,e.not_after,e.attempt_id,e.spki_sha256,e.csr_der,e.certificate_id,e.certificate_der,e.replaces_certificate_id FROM enrollments e JOIN pki_bindings p ON p.issuer_id=e.issuer_id WHERE e.id=?`, id).Scan(&v.id, &v.issuer, &v.principal, &v.profile, &v.tokenHash, &v.state, &v.created, &v.expires, &v.until, &v.attempt, &v.spki, &v.csr, &v.certificateID, &v.certificate, &v.replaces)
	if e != nil {
		return v, t.fail(ErrDenied)
	}
	return v, nil
}

func (t *Tx) renewalSource(v enrollment) error {
	if !v.replaces.Valid || v.state == "active" {
		return nil
	}
	var count int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM certificates c JOIN enrollments e ON e.certificate_id=c.id JOIN issuers i ON i.id=c.issuer_id WHERE c.id=? AND c.revoked=0 AND c.not_before<=? AND c.not_after>? AND e.state='active' AND i.enabled=1 AND i.not_after>?`, v.replaces.String, t.now.UnixNano(), t.now.UnixNano(), t.now.UnixNano()).Scan(&count)
	if e != nil {
		return t.fail(ErrStorage)
	}
	if count != 1 {
		return t.fail(ErrDenied)
	}
	return nil
}

// ReserveRenewal proves the current key on TLS and on an empty CSR. It can only
// renew the same ordinary key within existing enrollment authority. Activation
// atomically revokes the previous certificate; no implicit overlap is granted.
// Key replacement/overlap and all administrator renewals remain disabled.
func (s *Store) ReserveRenewal(ctx context.Context, id string, conn *tls.Conn, trust *pki.Trust, csrDER []byte, until time.Time) (string, error) {
	csr, e := pki.ParseCSR(csrDER)
	if e != nil || !validID(id) || conn == nil || trust == nil {
		return "", ErrInvalid
	}
	if conn.HandshakeContext(ctx) != nil {
		return "", ErrDenied
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return "", ErrDenied
	}
	var secret string
	e = s.Update(ctx, trust.IssuerID(), func(t *Tx) error {
		v, e := t.peer(trust, state.PeerCertificates[0].Raw, false)
		if e != nil {
			return e
		}
		if v.credential.Profile != pki.Device || pki.Hash(csr.RawSubjectPublicKeyInfo) != v.credential.SPKISHA256 || !until.Equal(until.Truncate(time.Second)) || !until.After(v.credential.NotAfter) {
			return t.fail(ErrDenied)
		}
		if e := t.enrollmentAuthority(trust.IssuerID(), v.credential.PrincipalID, pki.Device, until); e != nil {
			return e
		}
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return t.fail(ErrStorage)
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
		// The renewal ID is also its immutable attempt ID. Only one live renewal
		// reservation per old certificate is allowed, including uncertain signing.
		var outstanding int
		if e := t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM enrollments WHERE replaces_certificate_id=? AND state NOT IN ('revoked','failed')", v.certificateID).Scan(&outstanding); e != nil {
			return t.fail(ErrStorage)
		}
		if outstanding != 0 {
			return t.fail(ErrDenied)
		}
		if e := t.exec(`INSERT INTO enrollments(id,issuer_id,device_id,token_hash,created_at,expires_at,not_after,state,attempt_id,spki_sha256,csr_der,replaces_certificate_id) VALUES(?,?,?,?,?,?,?,'reserved',?,?,?,?)`, id, trust.IssuerID(), v.credential.PrincipalID, pki.Hash(b), t.now.UnixNano(), t.now.Add(10*time.Minute).UnixNano(), until.UnixNano(), id, v.credential.SPKISHA256, csr.Raw, v.certificateID); e != nil {
			return e
		}
		return t.event("enrollment.renew", id)
	})
	if e != nil {
		return "", e
	}
	return secret, nil
}

func validSecret(secret, hash string) bool {
	if len(secret) != 43 {
		return false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(secret)
	return e == nil && len(b) == 32 && subtle.ConstantTimeCompare([]byte(pki.Hash(b)), []byte(hash)) == 1
}

// ReserveEnrollment binds a token permanently to one attempt and public key.
// A retry may use another valid signature of the same empty CSR with that key.
func (s *Store) ReserveEnrollment(ctx context.Context, actor, id, secret, attempt string, csrDER []byte) error {
	return s.reserveEnrollment(ctx, actor, id, secret, attempt, csrDER, nil)
}

// A network redemption endpoint pins its configured issuer before reservation,
// so a token for another ordinary profile cannot be consumed at the wrong URL.
func (s *Store) reserveEnrollment(ctx context.Context, actor, id, secret, attempt string, csrDER []byte, trust *pki.Trust) error {
	csr, e := pki.ParseCSR(csrDER)
	if e != nil {
		return ErrInvalid
	}
	return s.Update(ctx, actor, func(t *Tx) error {
		if e := t.guard(validID(id) && validID(attempt)); e != nil {
			return e
		}
		v, e := t.enrollment(id)
		if e != nil {
			return e
		}
		if trust != nil {
			if e := t.trustBound(trust); e != nil {
				return e
			}
			if v.issuer != trust.IssuerID() || v.profile != trust.Profile() {
				return t.fail(ErrDenied)
			}
		}
		if !validSecret(secret, v.tokenHash) || t.now.UnixNano() < v.created || t.now.UnixNano() >= v.expires {
			return t.fail(ErrDenied)
		}
		if e := t.enrollmentAuthority(v.issuer, v.principal, v.profile, time.Unix(0, v.until)); e != nil {
			return e
		}
		if v.state != "invited" {
			if (v.state == "reserved" || v.state == "issuing" || v.state == "issued" || v.state == "active") && v.attempt.String == attempt && v.spki.String == pki.Hash(csr.RawSubjectPublicKeyInfo) {
				return nil
			}
			return t.fail(ErrDenied)
		}
		if e := t.exec("UPDATE enrollments SET state='reserved',attempt_id=?,spki_sha256=?,csr_der=? WHERE id=?", attempt, pki.Hash(csr.RawSubjectPublicKeyInfo), csr.Raw, id); e != nil {
			return e
		}
		return t.event("enrollment.reserve", id)
	})
}

// IssuanceRequest contains public material and server-approved constraints only.
// The provider must be a reviewed, restricted registration-authority adapter.
// No provider is installed by the executable; tests use an ephemeral real X.509 CA.
type IssuanceRequest = pki.IssuanceRequest

type IssuanceProvider interface {
	Issue(context.Context, IssuanceRequest) ([]byte, error)
}

func (t *Tx) trustBound(trust *pki.Trust) error {
	if trust == nil {
		return t.fail(ErrInvalid)
	}
	var count int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM pki_bindings WHERE issuer_id=? AND deployment_id=? AND profile=? AND root_sha256=? AND issuer_sha256=?`, trust.IssuerID(), trust.DeploymentID(), string(trust.Profile()), trust.RootFingerprint(), trust.IssuerFingerprint()).Scan(&count)
	if e != nil {
		return t.fail(ErrStorage)
	}
	if count != 1 {
		return t.fail(ErrDenied)
	}
	return nil
}

// IssueEnrollment makes at most one provider call for a reservation, even after
// a crash or ambiguous provider error. A stuck issuing state needs explicit
// reconciliation of the public result, or revocation and a new invitation.
func (s *Store) IssueEnrollment(ctx context.Context, actor, id string, trust *pki.Trust, provider IssuanceProvider) error {
	if provider == nil {
		return ErrInvalid
	}
	var request IssuanceRequest
	e := s.Update(ctx, actor, func(t *Tx) error {
		if e := t.guard(validID(id)); e != nil {
			return e
		}
		if e := t.trustBound(trust); e != nil {
			return e
		}
		v, e := t.enrollment(id)
		if e != nil {
			return e
		}
		if v.state != "reserved" || v.issuer != trust.IssuerID() || t.now.UnixNano() < v.created || t.now.UnixNano() >= v.expires {
			return t.fail(ErrDenied)
		}
		if e := t.renewalSource(v); e != nil {
			return e
		}
		if e := t.enrollmentAuthority(v.issuer, v.principal, v.profile, time.Unix(0, v.until)); e != nil {
			return e
		}
		request = IssuanceRequest{AttemptID: v.attempt.String, DeploymentID: trust.DeploymentID(), IssuerID: v.issuer, PrincipalID: v.principal, Profile: v.profile, CSR: bytes.Clone(v.csr), NotBefore: time.Unix(0, v.created).UTC().Truncate(time.Second), NotAfter: time.Unix(0, v.until).UTC()}
		if e := t.exec("UPDATE enrollments SET state='issuing' WHERE id=?", id); e != nil {
			return e
		}
		return t.event("enrollment.issuing", id)
	})
	if e != nil {
		return e
	}
	der, e := provider.Issue(ctx, request)
	// Do not propagate provider errors, which may contain credentials or bodies.
	if e != nil {
		return ErrDenied
	}
	return s.ReconcileEnrollment(ctx, actor, id, trust, der)
}

// ReconcileEnrollment is trusted operator/provider recovery, not a client API.
// It validates the exact signed result; possession of this public certificate
// does not activate it or grant access. No call retries signing automatically.
func (s *Store) ReconcileEnrollment(ctx context.Context, actor, id string, trust *pki.Trust, der []byte) error {
	der = bytes.Clone(der)
	return s.Update(ctx, actor, func(t *Tx) error {
		if e := t.guard(validID(id)); e != nil {
			return e
		}
		if e := t.trustBound(trust); e != nil {
			return e
		}
		v, e := t.enrollment(id)
		if e != nil {
			return e
		}
		if v.issuer != trust.IssuerID() || t.now.UnixNano() < v.created {
			return t.fail(ErrDenied)
		}
		if e := t.renewalSource(v); e != nil {
			return e
		}
		if e := t.enrollmentAuthority(v.issuer, v.principal, v.profile, time.Unix(0, v.until)); e != nil {
			return e
		}
		if v.state == "issued" || v.state == "active" {
			var revoked int
			if e := t.tx.QueryRowContext(t.ctx, "SELECT revoked FROM certificates WHERE id=?", v.certificateID.String).Scan(&revoked); e != nil || revoked != 0 {
				return t.fail(ErrDenied)
			}
			if bytes.Equal(v.certificate, der) {
				return nil
			}
			return t.fail(ErrDenied)
		}
		if v.state != "issuing" {
			return t.fail(ErrDenied)
		}
		c, e := trust.Verify(der, v.principal, t.now)
		if e != nil || c.SPKISHA256 != v.spki.String || !c.NotAfter.Equal(time.Unix(0, v.until)) || !c.NotBefore.Equal(time.Unix(0, v.created).Truncate(time.Second)) {
			return t.fail(ErrDenied)
		}
		certificateID := NewID()
		if e := t.RegisterCertificate(Certificate{certificateID, c.IssuerID, c.Serial, c.PrincipalID, string(c.Profile), c.LeafSHA256, c.SPKISHA256, c.NotBefore, c.NotAfter, false}); e != nil {
			return e
		}
		if e := t.exec("UPDATE enrollments SET state='issued',certificate_id=?,certificate_der=? WHERE id=?", certificateID, der, id); e != nil {
			return e
		}
		return t.event("enrollment.issued", id)
	})
}

// EnrollmentCertificate delivers public material only to the same valid
// invitation/attempt/key binding. Expired tokens cannot retrieve results.
func (s *Store) EnrollmentCertificate(ctx context.Context, actor, id, secret, attempt string, csr []byte) ([]byte, error) {
	r, e := pki.ParseCSR(csr)
	if e != nil {
		return nil, ErrInvalid
	}
	var result []byte
	e = s.Update(ctx, actor, func(t *Tx) error {
		v, e := t.enrollment(id)
		if e != nil {
			return e
		}
		if !validSecret(secret, v.tokenHash) || v.attempt.String != attempt || v.spki.String != pki.Hash(r.RawSubjectPublicKeyInfo) || t.now.UnixNano() < v.created || t.now.UnixNano() >= v.expires || (v.state != "issued" && v.state != "active") {
			return t.fail(ErrDenied)
		}
		if e := t.enrollmentAuthority(v.issuer, v.principal, v.profile, time.Unix(0, v.until)); e != nil {
			return e
		}
		result = bytes.Clone(v.certificate)
		var revoked int
		if e := t.tx.QueryRowContext(t.ctx, "SELECT revoked FROM certificates WHERE id=?", v.certificateID.String).Scan(&revoked); e != nil || revoked != 0 {
			return t.fail(ErrDenied)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return result, nil
}

func (t *Tx) RevokeEnrollment(id string) error {
	if e := t.guard(validID(id)); e != nil {
		return e
	}
	v, e := t.enrollment(id)
	if e != nil {
		return e
	}
	if v.state == "revoked" {
		return nil
	}
	if v.certificateID.Valid {
		if e := t.Disable("certificate", v.certificateID.String); e != nil {
			return e
		}
	}
	if e := t.exec("UPDATE enrollments SET state='revoked' WHERE id=?", id); e != nil {
		return e
	}
	return t.event("enrollment.revoke", id)
}
