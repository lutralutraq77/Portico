package controller

import (
	"context"
	"database/sql"
	"time"

	"portico.local/portico/internal/pki"
)

// policyQueries exposes only query methods; callers use fixed SELECT statements.
// Live authorization and administrator inspection share the same decision reads.
// Authorization wrappers retain the transaction's sticky failure semantics;
// inspection may describe a denial without issuing or changing any authority.
type policyQueries interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type policyReader struct {
	tx  policyQueries
	ctx context.Context
	now time.Time
}

func (t *Tx) readPolicy() policyReader { return policyReader{tx: t.tx, ctx: t.ctx, now: t.now} }

func (t policyReader) peer(trust *pki.Trust, der []byte, pending bool) (peer, error) {
	var v peer
	if err := t.trustBound(trust); err != nil {
		return v, err
	}
	var principal string
	err := t.tx.QueryRowContext(t.ctx, `SELECT coalesce(c.device_id,c.connector_id),c.id,e.id,e.state FROM certificates c JOIN enrollments e ON e.certificate_id=c.id WHERE c.leaf_sha256=? AND c.issuer_id=? AND c.profile=? AND c.revoked=0 AND c.not_before<=? AND c.not_after>? AND e.state IN ('issued','active')`, pki.Hash(der), trust.IssuerID(), string(trust.Profile()), t.now.UnixNano(), t.now.UnixNano()).Scan(&principal, &v.certificateID, &v.enrollmentID, &v.state)
	if err != nil {
		return v, policyReadError(err)
	}
	if !pending && v.state != "active" {
		return v, ErrDenied
	}
	v.credential, err = trust.Verify(der, principal, t.now)
	if err != nil {
		return v, ErrDenied
	}
	if err := t.enrollmentAuthority(trust.IssuerID(), principal, trust.Profile(), v.credential.NotAfter); err != nil {
		return v, err
	}
	if v.state == "issued" {
		var replaces sql.NullString
		if err := t.tx.QueryRowContext(t.ctx, "SELECT replaces_certificate_id FROM enrollments WHERE id=?", v.enrollmentID).Scan(&replaces); err != nil {
			return v, policyReadError(err)
		}
		if err := t.renewalSource(replaces, v.state); err != nil {
			return v, err
		}
	}
	return v, nil
}

func policyReadError(err error) error {
	if err == sql.ErrNoRows {
		return ErrDenied
	}
	return ErrStorage
}

func (t policyReader) trustBound(trust *pki.Trust) error {
	if trust == nil {
		return ErrInvalid
	}
	var count int
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM pki_bindings WHERE issuer_id=? AND deployment_id=? AND profile=? AND root_sha256=? AND issuer_sha256=?`, trust.IssuerID(), trust.DeploymentID(), string(trust.Profile()), trust.RootFingerprint(), trust.IssuerFingerprint()).Scan(&count)
	if err != nil {
		return ErrStorage
	}
	if count != 1 {
		return ErrDenied
	}
	return nil
}

func (t policyReader) enrollmentAuthority(issuer, principal string, profile pki.Profile, until time.Time) error {
	var issuerEnd int64
	if err := t.tx.QueryRowContext(t.ctx, `SELECT i.not_after FROM issuers i JOIN pki_bindings p ON p.issuer_id=i.id WHERE i.id=? AND i.enabled=1 AND p.profile=?`, issuer, string(profile)).Scan(&issuerEnd); err != nil {
		return policyReadError(err)
	}
	if !until.After(t.now) || until.UnixNano() > issuerEnd {
		return ErrDenied
	}
	var enabled int
	if profile == pki.Device {
		var end int64
		if err := t.tx.QueryRowContext(t.ctx, `SELECT d.enabled*u.enabled,d.not_after FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?`, principal).Scan(&enabled, &end); err != nil {
			return policyReadError(err)
		}
		if enabled != 1 || until.UnixNano() > end {
			return ErrDenied
		}
	} else if profile == pki.Connector {
		if err := t.tx.QueryRowContext(t.ctx, "SELECT enabled FROM connectors WHERE id=?", principal).Scan(&enabled); err != nil {
			return policyReadError(err)
		}
		if enabled != 1 {
			return ErrDenied
		}
	} else {
		return ErrDenied
	}
	return nil
}

func (t policyReader) renewalSource(replaces sql.NullString, state string) error {
	if !replaces.Valid || state == "active" {
		return nil
	}
	var count int
	err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM certificates c JOIN enrollments e ON e.certificate_id=c.id JOIN issuers i ON i.id=c.issuer_id WHERE c.id=? AND c.revoked=0 AND c.not_before<=? AND c.not_after>? AND e.state='active' AND i.enabled=1 AND i.not_after>?`, replaces.String, t.now.UnixNano(), t.now.UnixNano(), t.now.UnixNano()).Scan(&count)
	if err != nil {
		return ErrStorage
	}
	if count != 1 {
		return ErrDenied
	}
	return nil
}
