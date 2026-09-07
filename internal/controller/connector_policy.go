package controller

import (
	"context"
	"crypto/tls"
	"database/sql"
	"strings"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

// ConnectorCheck is sent only after the client verifies inner TLS and extracts
// that connection's actual leaf. A public DER supplied by a caller is not proof
// that it connected to that peer, and this response is not a session permit.
type ConnectorCheck = control.ConnectorCheck
type ConnectorStatus = control.ConnectorStatus

func (p *PolicyEngine) CheckConnector(ctx context.Context, c *tls.Conn, r ConnectorCheck) (ConnectorStatus, error) {
	if r.Version != PolicyProtocol || !validID(r.ResourceID) || r.Revision < 1 || len(r.ConnectorLeafDER) == 0 || len(r.ConnectorLeafDER) > pki.MaxDER {
		return ConnectorStatus{}, ErrDenied
	}
	der, e := adminDER(ctx, c)
	if e != nil {
		return ConnectorStatus{}, ErrDenied
	}
	var result ConnectorStatus
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		client, e := t.peer(p.config.DeviceTrust, der, false)
		if e != nil {
			return e
		}
		connector, e := t.peer(p.config.ConnectorTrust, r.ConnectorLeafDER, false)
		if e != nil {
			return e
		}
		m, e := p.match(t, client, connector, r.ResourceID, r.Revision)
		if e != nil {
			return e
		}
		revision, e := t.policyRevision()
		if e != nil {
			return e
		}
		result = ConnectorStatus{Version: PolicyProtocol, Resource: m.resource, ConnectorCertificateID: connector.certificateID, PolicyRevision: revision, CheckedAt: t.now}
		return nil
	})
	if e != nil {
		return ConnectorStatus{}, e
	}
	return result, nil
}

const MaxHostingResources = control.MaxHostingResources
const MaxCancellationBatch = control.MaxCancellationBatch

// These limits are shared across HTTP connections using this policy engine.
// Duplicate polling is allowed for recovery from an uncertain request, but
// authenticated peers cannot accumulate unbounded sleeping handlers.
const maxCancellationWaits = 128
const maxCertificateWaits = 2

func (p *PolicyEngine) acquireWait(certificate string) bool {
	p.waitMu.Lock()
	defer p.waitMu.Unlock()
	if p.waitCount >= maxCancellationWaits || p.waits[certificate] >= maxCertificateWaits {
		return false
	}
	p.waitCount++
	p.waits[certificate]++
	return true
}

func (p *PolicyEngine) releaseWait(certificate string) {
	p.waitMu.Lock()
	defer p.waitMu.Unlock()
	p.waitCount--
	p.waits[certificate]--
	if p.waits[certificate] == 0 {
		delete(p.waits, certificate)
	}
}

type HostingResource = control.HostingResource
type HostingSnapshot = control.HostingSnapshot

// Hosting returns a bounded, complete snapshot of current unambiguous hosting
// bindings for this connector certificate. It neither includes device grants nor
// confers dialing authority. A session still needs online Authorize and Activate.
func (p *PolicyEngine) Hosting(ctx context.Context, c *tls.Conn) (HostingSnapshot, error) {
	der, e := adminDER(ctx, c)
	if e != nil {
		return HostingSnapshot{}, ErrDenied
	}
	var result HostingSnapshot
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		connector, e := t.peer(p.config.ConnectorTrust, der, false)
		if e != nil {
			return e
		}
		gen, e := t.policyRevision()
		if e != nil {
			return e
		}
		until := t.now.Add(p.config.LeaseLifetime)
		if connector.credential.NotAfter.Before(until) {
			until = connector.credential.NotAfter
		}
		result = HostingSnapshot{Version: PolicyProtocol, ConnectorID: connector.credential.PrincipalID, ConnectorCertificateID: connector.certificateID, PolicyRevision: gen, CheckedAt: t.now, Until: until, Resources: []HostingResource{}}
		rows, e := t.tx.QueryContext(ctx, `SELECT r.id,r.revision,r.name,r.connector_id,k.name,r.address,r.port,r.protocol,h.id,h.valid_from,h.valid_until
 FROM resources r JOIN resource_heads rh ON rh.id=r.id AND rh.revision=r.revision
 JOIN connectors k ON k.id=r.connector_id
 JOIN host_bindings h ON h.resource_id=r.id AND h.revision=r.revision AND h.connector_id=r.connector_id
 WHERE k.id=? AND k.enabled=1 AND r.enabled=1 AND r.kind='application' AND h.enabled=1 AND h.valid_from<=? AND h.valid_until>?
 ORDER BY r.id,h.id LIMIT ?`, result.ConnectorID, t.now.UnixNano(), t.now.UnixNano(), MaxHostingResources+1)
		if e != nil {
			return t.fail(ErrStorage)
		}
		defer rows.Close()
		seen := map[string]bool{}
		for rows.Next() {
			var v HostingResource
			var from, end int64
			if rows.Scan(&v.Resource.ID, &v.Resource.Revision, &v.Resource.Name, &v.Resource.ConnectorID, &v.Resource.ConnectorName, &v.Resource.Address, &v.Resource.Port, &v.Resource.Protocol, &v.HostBindingID, &from, &end) != nil {
				return t.fail(ErrStorage)
			}
			if seen[v.Resource.ID] || len(result.Resources) >= MaxHostingResources || v.Resource.Protocol != "tcp" || !p.destination(v.Resource.Address) {
				return t.fail(ErrDenied)
			}
			seen[v.Resource.ID] = true
			v.From = time.Unix(0, from).UTC()
			v.Until = time.Unix(0, end).UTC()
			if connector.credential.NotAfter.Before(v.Until) {
				v.Until = connector.credential.NotAfter
			}
			v.Resource.Until = v.Until
			if v.Until.Before(result.Until) {
				result.Until = v.Until
			}
			result.Resources = append(result.Resources, v)
		}
		if rows.Err() != nil {
			return t.fail(ErrStorage)
		}
		return nil
	})
	if e != nil {
		return HostingSnapshot{}, e
	}
	return result, nil
}

type CancellationRequest = control.CancellationRequest
type Cancellation = control.Cancellation
type CancellationBatch = control.CancellationBatch
type CancellationAck = control.CancellationAck

// expireOwned records a bounded set of expired leases as cancellation targets.
// Repeated polls make progress without an unbounded transaction or cursor gaps.
func (p *PolicyEngine) expireOwned(t *Tx, connector peer) error {
	rows, e := t.tx.QueryContext(t.ctx, `SELECT s.id FROM sessions s JOIN authorized_sessions a ON a.id=s.id
 WHERE s.connector_certificate_id=? AND a.connector_id=? AND s.state='requested' AND (s.not_after<=? OR a.lease_until<=?) ORDER BY s.id LIMIT ?`, connector.certificateID, connector.credential.PrincipalID, t.now.UnixNano(), t.now.UnixNano(), MaxCancellationBatch)
	if e != nil {
		return t.fail(ErrStorage)
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			_ = rows.Close()
			return t.fail(ErrStorage)
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return t.fail(ErrStorage)
	}
	for _, id := range ids {
		if e = t.EndSession(id, "expired"); e != nil {
			return e
		}
	}
	return nil
}

// Cancellations repeats unacknowledged immutable targets for the exact original
// connector certificate. Missing, retried and reordered polls cannot skip work.
func (p *PolicyEngine) Cancellations(ctx context.Context, c *tls.Conn, r CancellationRequest) (CancellationBatch, error) {
	if !r.Valid() {
		return CancellationBatch{}, ErrDenied
	}
	// Subscribe before reading, so a commit between the read and wait cannot
	// be lost. A wakeup prompts another authenticated, authoritative read.
	changed := p.store.changes()
	batch, e := p.cancellations(ctx, c, r)
	if e != nil || len(batch.Items) > 0 || r.WaitMillis == 0 {
		return batch, e
	}
	if !p.acquireWait(batch.ConnectorCertificateID) {
		return CancellationBatch{}, ErrDenied
	}
	defer p.releaseWait(batch.ConnectorCertificateID)
	timer := time.NewTimer(time.Duration(r.WaitMillis) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	case <-ctx.Done():
		return CancellationBatch{}, ErrDenied
	}
	return p.cancellations(ctx, c, r)
}

func (p *PolicyEngine) cancellations(ctx context.Context, c *tls.Conn, r CancellationRequest) (CancellationBatch, error) {
	der, e := adminDER(ctx, c)
	if e != nil {
		return CancellationBatch{}, ErrDenied
	}
	var result CancellationBatch
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		connector, e := t.peer(p.config.ConnectorTrust, der, false)
		if e != nil {
			return e
		}
		t.actor = connector.credential.PrincipalID
		if e = p.expireOwned(t, connector); e != nil {
			return e
		}
		gen, e := t.policyRevision()
		if e != nil {
			return e
		}
		result = CancellationBatch{Version: PolicyProtocol, ConnectorCertificateID: connector.certificateID, PolicyRevision: gen, ObservedAt: t.now, Items: []Cancellation{}}
		query := `SELECT c.session_id,c.reason FROM session_cancellations c JOIN authorized_sessions a ON a.id=c.session_id JOIN sessions s ON s.id=a.id
 LEFT JOIN session_closure_receipts r ON r.session_id=c.session_id WHERE a.connector_id=? AND s.connector_certificate_id=? AND r.session_id IS NULL`
		args := []any{t.actor, connector.certificateID}
		if len(r.SessionIDs) > 0 {
			query += " AND c.session_id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(r.SessionIDs)), ",") + ")"
			for _, id := range r.SessionIDs {
				args = append(args, id)
			}
		}
		args = append(args, r.Limit)
		rows, e := t.tx.QueryContext(ctx, query+" ORDER BY c.rowid LIMIT ?", args...)
		if e != nil {
			return t.fail(ErrStorage)
		}
		defer rows.Close()
		for rows.Next() {
			var item Cancellation
			if rows.Scan(&item.SessionID, &item.Reason) != nil {
				return t.fail(ErrStorage)
			}
			result.Items = append(result.Items, item)
		}
		if rows.Err() != nil {
			return t.fail(ErrStorage)
		}
		return nil
	})
	if e != nil {
		return CancellationBatch{}, e
	}
	return result, nil
}

// AcknowledgeCancellation records the owner's report only. The connector must
// close its actual handles and join forwarding workers before calling it. TLS
// authenticates that report; it cannot prove a compromised connector's honesty.
func (p *PolicyEngine) AcknowledgeCancellation(ctx context.Context, c *tls.Conn, r CancellationAck) error {
	if r.Version != PolicyProtocol || !validID(r.SessionID) {
		return ErrDenied
	}
	der, e := adminDER(ctx, c)
	if e != nil {
		return ErrDenied
	}
	return p.store.Update(ctx, NewID(), func(t *Tx) error {
		connector, e := t.peer(p.config.ConnectorTrust, der, false)
		if e != nil {
			return e
		}
		t.actor = connector.credential.PrincipalID
		var state, authorized string
		e = t.tx.QueryRowContext(ctx, `SELECT s.state,a.state FROM sessions s JOIN authorized_sessions a ON a.id=s.id JOIN session_cancellations c ON c.session_id=s.id WHERE s.id=? AND s.connector_certificate_id=? AND a.connector_id=?`, r.SessionID, connector.certificateID, t.actor).Scan(&state, &authorized)
		if e != nil || state == "requested" || authorized != "closed" {
			return t.fail(ErrDenied)
		}
		var owner string
		e = t.tx.QueryRowContext(ctx, "SELECT connector_certificate_id FROM session_closure_receipts WHERE session_id=?", r.SessionID).Scan(&owner)
		if e == nil {
			if owner != connector.certificateID {
				return t.fail(ErrIntegrity)
			}
			return nil
		}
		if e != sql.ErrNoRows {
			return t.fail(ErrStorage)
		}
		if e = t.exec("INSERT INTO session_closure_receipts VALUES(?,?,?)", r.SessionID, connector.certificateID, t.now.UnixNano()); e != nil {
			return e
		}
		return t.event("session.closure_report", r.SessionID)
	})
}
