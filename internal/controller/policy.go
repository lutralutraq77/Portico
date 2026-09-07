package controller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"portico.local/portico/internal/pki"
)

const PolicyProtocol = 1

type PolicyConfig struct {
	DeviceTrust, ConnectorTrust                          *pki.Trust
	ProtectedNetworks                                    []netip.Prefix
	MaxSessions, MaxDeviceSessions, MaxConnectorSessions int
	SessionLifetime, LeaseLifetime, ActivationLifetime   time.Duration
}

// PolicyEngine is the online resource authorization boundary. It cannot dial a
// destination. Connector transport must verify the client's inner TLS proof
// before reporting its leaf; a compromised connector already owns its sockets.
type PolicyEngine struct {
	store  *Store
	config PolicyConfig
	hash   string
}

func NewPolicyEngine(s *Store, c PolicyConfig) (*PolicyEngine, error) {
	if s == nil || c.DeviceTrust == nil || c.ConnectorTrust == nil || c.DeviceTrust.Profile() != pki.Device || c.ConnectorTrust.Profile() != pki.Connector || c.DeviceTrust.DeploymentID() != c.ConnectorTrust.DeploymentID() || c.DeviceTrust.IssuerID() == c.ConnectorTrust.IssuerID() || len(c.ProtectedNetworks) == 0 || len(c.ProtectedNetworks) > 256 || c.MaxSessions < 1 || c.MaxSessions > 4096 || c.MaxDeviceSessions < 1 || c.MaxDeviceSessions > c.MaxSessions || c.MaxConnectorSessions < 1 || c.MaxConnectorSessions > c.MaxSessions || c.SessionLifetime <= 0 || c.SessionLifetime > time.Hour || c.LeaseLifetime <= 0 || c.LeaseLifetime > 15*time.Second || c.ActivationLifetime <= 0 || c.ActivationLifetime > 5*time.Second || c.ActivationLifetime > c.LeaseLifetime {
		return nil, ErrInvalid
	}
	c.ProtectedNetworks = append([]netip.Prefix(nil), c.ProtectedNetworks...)
	for _, p := range c.ProtectedNetworks {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return nil, ErrInvalid
		}
	}
	sort.Slice(c.ProtectedNetworks, func(i, j int) bool { return c.ProtectedNetworks[i].String() < c.ProtectedNetworks[j].String() })
	b, _ := json.Marshal(struct {
		Deployment, DeviceIssuer, ConnectorIssuer, DeviceRoot, DeviceCA, ConnectorRoot, ConnectorCA string
		Networks                                                                                    []netip.Prefix
		Global, Device, Connector                                                                   int
		Session, Lease, Activation                                                                  time.Duration
	}{c.DeviceTrust.DeploymentID(), c.DeviceTrust.IssuerID(), c.ConnectorTrust.IssuerID(), c.DeviceTrust.RootFingerprint(), c.DeviceTrust.IssuerFingerprint(), c.ConnectorTrust.RootFingerprint(), c.ConnectorTrust.IssuerFingerprint(), c.ProtectedNetworks, c.MaxSessions, c.MaxDeviceSessions, c.MaxConnectorSessions, c.SessionLifetime, c.LeaseLifetime, c.ActivationLifetime})
	return &PolicyEngine{store: s, config: c, hash: pki.Hash(b)}, nil
}

func (p *PolicyEngine) destination(address string) bool {
	canonical, e := literal(address)
	if e != nil || canonical != address {
		return false
	}
	a := netip.MustParseAddr(canonical)
	for _, block := range p.config.ProtectedNetworks {
		if block.Contains(a) {
			return false
		}
	}
	return true
}

type AuthorizeRequest struct {
	Version       int
	ClientLeafDER []byte
	ResourceID    string
	Revision      int64
}
type SessionRequest struct {
	Version   int
	SessionID string
	Sequence  int64
}
type ResourceAccess struct {
	ID                                                  string
	Revision                                            int64
	Name, ConnectorID, ConnectorName, Address, Protocol string
	Port                                                int
	Until                                               time.Time
}
type Authorization struct {
	Version                                                                 int
	SessionID, DeviceID, ConnectorID, CertificateID, ConnectorCertificateID string
	Resource                                                                ResourceAccess
	Sequence, PolicyRevision                                                int64
	IssuedAt, LeaseUntil, ActivateUntil, SessionUntil                       time.Time
}
type policyMatch struct {
	resource          ResourceAccess
	user, grant, host string
	until             time.Time
}

func (t *Tx) policyRevision() (int64, error) {
	var n int64
	if e := t.tx.QueryRowContext(t.ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&n); e != nil {
		return 0, t.fail(ErrStorage)
	}
	return n, nil
}

// match rejects ambiguous grants or hosting bindings. IDs/names supplied by a
// client are never substituted for the authenticated principal or destination.
func (p *PolicyEngine) match(t *Tx, client, connector peer, id string, revision int64) (policyMatch, error) {
	var m policyMatch
	if !validID(id) || revision < 1 || client.credential.Profile != pki.Device || connector.credential.Profile != pki.Connector {
		return m, t.fail(ErrDenied)
	}
	now := t.now.UnixNano()
	rows, e := t.tx.QueryContext(t.ctx, `SELECT r.id,r.revision,r.name,r.connector_id,k.name,r.address,r.port,r.protocol,d.user_id,g.id,h.id,min(d.not_after,g.valid_until,h.valid_until)
 FROM resources r JOIN resource_heads rh ON rh.id=r.id AND rh.revision=r.revision
 JOIN connectors k ON k.id=r.connector_id
 JOIN grants g ON g.resource_id=r.id AND g.revision=r.revision
 JOIN devices d ON d.id=g.device_id AND d.user_id=g.user_id JOIN users u ON u.id=d.user_id
 JOIN host_bindings h ON h.resource_id=r.id AND h.revision=r.revision AND h.connector_id=r.connector_id
 WHERE r.id=? AND r.revision=? AND d.id=? AND k.id=? AND r.enabled=1 AND r.kind='application' AND k.enabled=1 AND u.enabled=1 AND d.enabled=1
 AND g.enabled=1 AND h.enabled=1 AND g.valid_from<=? AND g.valid_until>? AND h.valid_from<=? AND h.valid_until>? AND d.not_after>? LIMIT 2`, id, revision, client.credential.PrincipalID, connector.credential.PrincipalID, now, now, now, now, now)
	if e != nil {
		return m, t.fail(ErrStorage)
	}
	defer func() { _ = rows.Close() }()
	var bound int64
	if !rows.Next() {
		if rows.Err() != nil {
			return m, t.fail(ErrStorage)
		}
		return m, t.fail(ErrDenied)
	}
	if rows.Scan(&m.resource.ID, &m.resource.Revision, &m.resource.Name, &m.resource.ConnectorID, &m.resource.ConnectorName, &m.resource.Address, &m.resource.Port, &m.resource.Protocol, &m.user, &m.grant, &m.host, &bound) != nil {
		return m, t.fail(ErrStorage)
	}
	if rows.Next() || rows.Err() != nil || m.resource.Protocol != "tcp" || !p.destination(m.resource.Address) {
		return m, t.fail(ErrDenied)
	}
	m.until = time.Unix(0, bound).UTC()
	for _, end := range []time.Time{client.credential.NotAfter, connector.credential.NotAfter, t.now.Add(p.config.SessionLifetime)} {
		if end.Before(m.until) {
			m.until = end
		}
	}
	if !m.until.After(t.now) {
		return m, t.fail(ErrDenied)
	}
	m.resource.Until = m.until
	return m, nil
}

func (p *PolicyEngine) quota(t *Tx, client, connector string) error {
	var total, device, server int
	e := t.tx.QueryRowContext(t.ctx, `SELECT count(*),coalesce(sum(s.device_id=?),0),coalesce(sum(a.connector_id=?),0) FROM authorized_sessions a JOIN sessions s ON s.id=a.id WHERE a.state IN ('authorized','active') AND s.state='requested' AND a.lease_until>?`, client, connector, t.now.UnixNano()).Scan(&total, &device, &server)
	if e != nil {
		return t.fail(ErrStorage)
	}
	if total >= p.config.MaxSessions || device >= p.config.MaxDeviceSessions || server >= p.config.MaxConnectorSessions {
		return t.fail(ErrDenied)
	}
	return nil
}

func (p *PolicyEngine) response(t *Tx, id string, client, connector peer, m policyMatch, sequence int64, sessionEnd time.Time) (Authorization, error) {
	gen, e := t.policyRevision()
	if e != nil {
		return Authorization{}, e
	}
	end := t.now.Add(p.config.LeaseLifetime)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	activation := t.now.Add(p.config.ActivationLifetime)
	if end.Before(activation) {
		activation = end
	}
	m.resource.Until = sessionEnd
	return Authorization{Version: PolicyProtocol, SessionID: id, DeviceID: client.credential.PrincipalID, ConnectorID: connector.credential.PrincipalID, CertificateID: client.certificateID, ConnectorCertificateID: connector.certificateID, Resource: m.resource, Sequence: sequence, PolicyRevision: gen, IssuedAt: t.now, LeaseUntil: end, ActivateUntil: activation, SessionUntil: sessionEnd}, nil
}

func (p *PolicyEngine) Authorize(ctx context.Context, conn *tls.Conn, r AuthorizeRequest) (Authorization, error) {
	if r.Version != PolicyProtocol || !validID(r.ResourceID) || r.Revision < 1 || len(r.ClientLeafDER) == 0 || len(r.ClientLeafDER) > pki.MaxDER {
		return Authorization{}, ErrDenied
	}
	der, e := adminDER(ctx, conn)
	if e != nil {
		return Authorization{}, ErrDenied
	}
	var result Authorization
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		connector, e := t.peer(p.config.ConnectorTrust, der, false)
		if e != nil {
			return e
		}
		client, e := t.peer(p.config.DeviceTrust, r.ClientLeafDER, false)
		if e != nil {
			return e
		}
		t.actor = connector.credential.PrincipalID
		m, e := p.match(t, client, connector, r.ResourceID, r.Revision)
		if e != nil {
			return e
		}
		if e = p.quota(t, client.credential.PrincipalID, connector.credential.PrincipalID); e != nil {
			return e
		}
		id := NewID()
		result, e = p.response(t, id, client, connector, m, 1, m.until)
		if e != nil {
			return e
		}
		if e = t.RecordSession(Session{ID: id, DeviceID: client.credential.PrincipalID, CertificateID: client.certificateID, ConnectorCertificateID: connector.certificateID, ResourceID: m.resource.ID, Revision: m.resource.Revision, GrantID: m.grant, HostBindingID: m.host, Until: m.until}); e != nil {
			return e
		}
		if e = t.exec("INSERT INTO authorized_sessions VALUES(?,?,?,?,?,'authorized',?,?,?,?,?)", id, result.ConnectorID, m.resource.Address, m.resource.Port, m.resource.Protocol, result.Sequence, result.LeaseUntil.UnixNano(), result.ActivateUntil.UnixNano(), result.PolicyRevision, p.hash); e != nil {
			return e
		}
		return t.event("session.authorize", id)
	})
	if e != nil {
		return Authorization{}, e
	}
	return result, nil
}

// Activate/Renew accept a sequence only from the same connector certificate.
// Neither the session ID nor a previously returned authorization is a bearer
// credential. Every transition rechecks the original client certificate and
// exact grant/binding; switching to another matching grant requires a new session.
func (p *PolicyEngine) transition(ctx context.Context, conn *tls.Conn, r SessionRequest, activate bool) (Authorization, error) {
	if r.Version != PolicyProtocol || !validID(r.SessionID) || r.Sequence < 1 {
		return Authorization{}, ErrDenied
	}
	der, e := adminDER(ctx, conn)
	if e != nil {
		return Authorization{}, ErrDenied
	}
	var result Authorization
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		connector, e := t.peer(p.config.ConnectorTrust, der, false)
		if e != nil {
			return e
		}
		t.actor = connector.credential.PrincipalID
		var deviceDER []byte
		var resource, grant, host, address, protocol, hash, state string
		var revision, sequence, lease, activation, end int64
		var port int
		e = t.tx.QueryRowContext(ctx, `SELECT e.certificate_der,s.resource_id,s.revision,s.grant_id,s.host_binding_id,a.address,a.port,a.protocol,a.state,a.lease_sequence,a.lease_until,a.activate_until,s.not_after,a.config_sha256 FROM authorized_sessions a JOIN sessions s ON s.id=a.id JOIN enrollments e ON e.certificate_id=s.certificate_id WHERE a.id=? AND a.connector_id=? AND s.connector_certificate_id=? AND s.state='requested'`, r.SessionID, connector.credential.PrincipalID, connector.certificateID).Scan(&deviceDER, &resource, &revision, &grant, &host, &address, &port, &protocol, &state, &sequence, &lease, &activation, &end, &hash)
		if e != nil || sequence != r.Sequence || hash != p.hash || t.now.UnixNano() >= lease || t.now.UnixNano() >= end || (activate && (state != "authorized" || t.now.UnixNano() >= activation)) || (!activate && state != "active") {
			return t.fail(ErrDenied)
		}
		client, e := t.peer(p.config.DeviceTrust, deviceDER, false)
		if e != nil {
			return e
		}
		m, e := p.match(t, client, connector, resource, revision)
		if e != nil {
			return e
		}
		if m.grant != grant || m.host != host || m.resource.Address != address || m.resource.Port != port || m.resource.Protocol != protocol {
			return t.fail(ErrDenied)
		}
		until := time.Unix(0, end).UTC()
		if m.until.Before(until) {
			until = m.until
		}
		result, e = p.response(t, r.SessionID, client, connector, m, sequence+1, until)
		if e != nil {
			return e
		}
		if e = t.exec("UPDATE authorized_sessions SET state='active',lease_sequence=?,lease_until=?,policy_revision=? WHERE id=?", result.Sequence, result.LeaseUntil.UnixNano(), result.PolicyRevision, r.SessionID); e != nil {
			return e
		}
		if e = t.exec("UPDATE sessions SET not_after=? WHERE id=?", until.UnixNano(), r.SessionID); e != nil {
			return e
		}
		action := "session.renew"
		if activate {
			action = "session.activate"
		}
		return t.event(action, r.SessionID)
	})
	if e != nil {
		return Authorization{}, e
	}
	return result, nil
}
func (p *PolicyEngine) Activate(ctx context.Context, c *tls.Conn, r SessionRequest) (Authorization, error) {
	return p.transition(ctx, c, r, true)
}
func (p *PolicyEngine) Renew(ctx context.Context, c *tls.Conn, r SessionRequest) (Authorization, error) {
	return p.transition(ctx, c, r, false)
}

func (p *PolicyEngine) CloseSession(ctx context.Context, c *tls.Conn, r SessionRequest) error {
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
		var count int
		if t.tx.QueryRowContext(ctx, "SELECT count(*) FROM authorized_sessions a JOIN sessions s ON s.id=a.id WHERE a.id=? AND a.connector_id=? AND s.connector_certificate_id=?", r.SessionID, t.actor, connector.certificateID).Scan(&count) != nil || count != 1 {
			return t.fail(ErrDenied)
		}
		return t.EndSession(r.SessionID, "closed")
	})
}

// Catalog exposes only currently usable, unambiguous application resources for
// this exact enrolled device. Future devices never inherit another device's grants.
func (p *PolicyEngine) Catalog(ctx context.Context, c *tls.Conn) ([]ResourceAccess, error) {
	der, e := adminDER(ctx, c)
	if e != nil {
		return nil, ErrDenied
	}
	result := []ResourceAccess{}
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		client, e := t.peer(p.config.DeviceTrust, der, false)
		if e != nil {
			return e
		}
		rows, e := t.tx.QueryContext(ctx, `SELECT DISTINCT r.id,r.revision,e.certificate_der FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision JOIN grants g ON g.resource_id=r.id AND g.revision=r.revision JOIN certificates c ON c.connector_id=r.connector_id JOIN enrollments e ON e.certificate_id=c.id WHERE g.device_id=? AND g.enabled=1 AND c.issuer_id=? AND c.revoked=0 AND e.state='active' ORDER BY r.id,c.id LIMIT 513`, client.credential.PrincipalID, p.config.ConnectorTrust.IssuerID())
		if e != nil {
			return t.fail(ErrStorage)
		}
		type candidate struct {
			id       string
			revision int64
			der      []byte
		}
		var candidates []candidate
		for rows.Next() {
			var v candidate
			if rows.Scan(&v.id, &v.revision, &v.der) != nil {
				_ = rows.Close()
				return t.fail(ErrStorage)
			}
			candidates = append(candidates, v)
		}
		rowErr := rows.Err()
		_ = rows.Close()
		if rowErr != nil || len(candidates) > 512 {
			return t.fail(ErrDenied)
		}
		seen := map[string]bool{}
		for _, v := range candidates {
			if seen[v.id] {
				continue
			}
			// A denied candidate is filtered; storage/integrity failures abort the
			// complete catalog. A separate Tx wrapper preserves the outer latch.
			probe := *t
			connector, e := probe.peer(p.config.ConnectorTrust, v.der, false)
			if e != nil {
				if e == ErrDenied || e == ErrConflict {
					continue
				}
				return e
			}
			m, e := p.match(&probe, client, connector, v.id, v.revision)
			if e != nil {
				if e == ErrDenied || e == ErrConflict {
					continue
				}
				return e
			}
			seen[v.id] = true
			result = append(result, m.resource)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return result, nil
}
