package controller

import (
	"database/sql"
	"time"

	"portico.local/portico/internal/pki"
)

// Audit exposes only the immutable event envelope. It contains no operation
// body, invitation secret, factor credential or authentication response.
type DashboardAudit struct {
	ID, ActorID, CorrelationID, Action, TargetID, PreviousHash, Hash string
	Sequence, Generation                                             int64
	OccurredAt                                                       time.Time
}

// Factor counts describe stored records, not physical authenticator custody.
// This view is limited to the actual administrator presenting the TLS leaf.
type DashboardSecurity struct {
	ID, UserName, DeviceID, DeviceName, CertificateFingerprint string
	CertificateExpiresAt, BootstrapUntil                       time.Time
	EnabledFactors, TestedEnabledFactors                       int
}

func dashboardAudit(tx *Tx, request DashboardRequest) ([]DashboardAudit, string, error) {
	// Reuse the audit export verifier without exporting or acknowledging events.
	// The enclosing request context bounds verification and all database reads.
	if err := verifyAudit(tx.ctx, tx.tx); err != nil {
		return nil, "", tx.fail(err)
	}
	if request.After != "" {
		var sequence int64
		if err := tx.tx.QueryRowContext(tx.ctx, "SELECT sequence FROM audit_events WHERE event_id=?", request.After).Scan(&sequence); err == sql.ErrNoRows {
			return nil, "", tx.fail(ErrConflict)
		} else if err != nil {
			return nil, "", tx.fail(ErrStorage)
		}
	}
	// Public event IDs are stable cursors; ordering is by audit sequence, never
	// by randomly generated IDs. A missing nonempty cursor was rejected above.
	return dashboardRows(tx, request, "SELECT event_id,sequence,occurred_at,actor_id,correlation_id,action,target_id,generation,previous_hash,hash FROM audit_events WHERE sequence>COALESCE((SELECT sequence FROM audit_events WHERE event_id=?),0) ORDER BY sequence LIMIT ?", func(rows *sql.Rows) (DashboardAudit, string, error) {
		var v DashboardAudit
		var occurred int64
		err := rows.Scan(&v.ID, &v.Sequence, &occurred, &v.ActorID, &v.CorrelationID, &v.Action, &v.TargetID, &v.Generation, &v.PreviousHash, &v.Hash)
		v.OccurredAt = time.Unix(0, occurred).UTC()
		return v, v.ID, err
	})
}

func dashboardSecurity(tx *Tx, request DashboardRequest, peer adminPeer, trust *pki.Trust, der []byte) ([]DashboardSecurity, string, error) {
	if request.After != "" {
		return nil, "", tx.fail(ErrInvalid)
	}
	credential, err := trust.Verify(der, peer.device, tx.now)
	if err != nil {
		return nil, "", tx.fail(ErrDenied)
	}
	v := DashboardSecurity{ID: peer.user, DeviceID: peer.device, CertificateFingerprint: peer.hash, CertificateExpiresAt: credential.NotAfter, BootstrapUntil: time.Unix(0, peer.bootstrapUntil).UTC()}
	if err := tx.tx.QueryRowContext(tx.ctx, "SELECT u.name,d.name FROM users u JOIN devices d ON d.user_id=u.id WHERE u.id=? AND d.id=?", peer.user, peer.device).Scan(&v.UserName, &v.DeviceName); err != nil {
		return nil, "", tx.fail(ErrStorage)
	}
	if err := tx.tx.QueryRowContext(tx.ctx, "SELECT count(*),COALESCE(sum(tested),0) FROM admin_factors WHERE user_id=? AND enabled=1", peer.user).Scan(&v.EnabledFactors, &v.TestedEnabledFactors); err != nil {
		return nil, "", tx.fail(ErrStorage)
	}
	if v.EnabledFactors < 0 || v.TestedEnabledFactors < 0 || v.TestedEnabledFactors > v.EnabledFactors {
		return nil, "", tx.fail(ErrIntegrity)
	}
	return []DashboardSecurity{v}, "", nil
}
