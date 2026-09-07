package controller

import (
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/pki"
)

type peer struct {
	credential                         pki.Credential
	certificateID, enrollmentID, state string
}

func (t *Tx) peer(trust *pki.Trust, der []byte, pending bool) (peer, error) {
	var v peer
	if e := t.trustBound(trust); e != nil {
		return v, e
	}
	var principal string
	e := t.tx.QueryRowContext(t.ctx, `SELECT coalesce(c.device_id,c.connector_id),c.id,e.id,e.state FROM certificates c JOIN enrollments e ON e.certificate_id=c.id WHERE c.leaf_sha256=? AND c.issuer_id=? AND c.profile=? AND c.revoked=0 AND c.not_before<=? AND c.not_after>? AND e.state IN ('issued','active')`, pki.Hash(der), trust.IssuerID(), string(trust.Profile()), t.now.UnixNano(), t.now.UnixNano()).Scan(&principal, &v.certificateID, &v.enrollmentID, &v.state)
	if e != nil || (!pending && v.state != "active") {
		return v, t.fail(ErrDenied)
	}
	v.credential, e = trust.Verify(der, principal, t.now)
	if e != nil {
		return v, t.fail(ErrDenied)
	}
	if e = t.enrollmentAuthority(trust.IssuerID(), principal, trust.Profile(), v.credential.NotAfter); e != nil {
		return v, e
	}
	if v.state == "issued" {
		enrollment, e := t.enrollment(v.enrollmentID)
		if e != nil {
			return v, e
		}
		if e := t.renewalSource(enrollment); e != nil {
			return v, e
		}
	}
	return v, nil
}

// ClientTLSConfig configures a TLS 1.3 server-side client-certificate boundary.
// The caller supplies its separate management server identity. It must not add
// insecure callbacks/key logging or expose the pending-enrollment listener as an
// application API. A successful handshake conveys identity, not resource access.
// Session tickets are disabled so each connection proves possession again.
func (s *Store) ClientTLSConfig(serverIdentity tls.Certificate, trust *pki.Trust, pendingEnrollment bool) (*tls.Config, error) {
	if trust == nil || len(serverIdentity.Certificate) == 0 || serverIdentity.PrivateKey == nil {
		return nil, ErrInvalid
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 {
			return ErrDenied
		}
		// Contexts are bounded even if a future listener lacks its own deadline.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Update(ctx, trust.IssuerID(), func(t *Tx) error { _, e := t.peer(trust, state.PeerCertificates[0].Raw, pendingEnrollment); return e })
	}
	return config, nil
}

// Authenticate rechecks live authority after a completed real TLS handshake.
// Call again at each authorization boundary; existing streams need the later
// phase's cancellation/lease machinery and are not kept valid by this result.
func (s *Store) Authenticate(ctx context.Context, conn *tls.Conn, trust *pki.Trust) (pki.Credential, error) {
	var result pki.Credential
	if conn == nil || trust == nil || conn.HandshakeContext(ctx) != nil {
		return result, ErrDenied
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return result, ErrDenied
	}
	e := s.Update(ctx, trust.IssuerID(), func(t *Tx) error {
		v, e := t.peer(trust, state.PeerCertificates[0].Raw, false)
		if e != nil {
			return e
		}
		result = v.credential
		return nil
	})
	if e != nil {
		return pki.Credential{}, e
	}
	return result, nil
}

// ActivateEnrollment requires a fresh connection proving the issued private
// key. Public DER, invitation tokens or a forged ConnectionState are insufficient.
func (s *Store) ActivateEnrollment(ctx context.Context, id string, conn *tls.Conn, trust *pki.Trust) error {
	if !validID(id) || conn == nil || trust == nil || conn.HandshakeContext(ctx) != nil {
		return ErrDenied
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return ErrDenied
	}
	return s.Update(ctx, trust.IssuerID(), func(t *Tx) error {
		v, e := t.peer(trust, state.PeerCertificates[0].Raw, true)
		if e != nil {
			return e
		}
		if v.enrollmentID != id {
			return t.fail(ErrDenied)
		}
		if v.state == "active" {
			return nil
		}
		enrollment, e := t.enrollment(id)
		if e != nil {
			return e
		}
		if enrollment.replaces.Valid {
			if e := t.Disable("certificate", enrollment.replaces.String); e != nil {
				return e
			}
		}
		if e := t.exec("UPDATE enrollments SET state='active' WHERE id=? AND state='issued'", id); e != nil {
			return e
		}
		return t.event("enrollment.activate", id)
	})
}
