package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"time"

	"portico.local/portico/internal/pki"
)

// ManagementRouteConfig is trusted local configuration for one dedicated
// management connector and exact resource revision. It is never decoded from a
// browser or an ordinary device request. The connector certificate identifies
// the configured route; possession is checked separately by its transport.
type ManagementRouteConfig struct {
	Administrators, Connectors *pki.Trust
	ConnectorLeafDER           []byte
	ResourceID, ConnectorID    string
	Revision                   int64
	Address                    string
	Port                       int
}

// ManagementRoute checks access at the private HTTPS destination itself.
// A successful check is a current observation, not a session, lease or bearer
// permit. The routing runtime must still authenticate its connector and own
// its bounded streams. Ordinary PolicyEngine authorization remains unchanged.
type ManagementRoute struct {
	store  *Store
	config ManagementRouteConfig
	hash   string
}

type ManagementAccess struct {
	Version                                    int
	DeviceID, UserID, CertificateFingerprint   string
	Resource                                   ResourceAccess
	ConnectorCertificateID, GrantID, BindingID string
	RouteFingerprint                           string
	PolicyRevision                             int64
	CheckedAt                                  time.Time
}

type managementRequestKey struct{}
type managementRequest struct {
	route *ManagementRoute
	leaf  []byte
}

// Only the private HTTP server installs this context, after extracting the
// actual TLS peer. Store.Update rechecks it inside every request transaction,
// so revocation between HTTP dispatch and a sensitive mutation cannot race the
// management grant. It is neither a serialized field nor a forwarding header.
func (m *ManagementRoute) requestContext(ctx context.Context, conn *tls.Conn) (context.Context, error) {
	if _, err := m.Check(ctx, conn); err != nil {
		return nil, err
	}
	der, err := adminDER(ctx, conn)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, managementRequestKey{}, managementRequest{m, der}), nil
}

func (s *Store) checkManagementRequest(t *Tx) error {
	request, ok := t.ctx.Value(managementRequestKey{}).(managementRequest)
	if !ok {
		return nil
	}
	if request.route == nil || request.route.store != s {
		return t.fail(ErrDenied)
	}
	_, err := request.route.check(t, request.leaf)
	return err
}

func NewManagementRoute(s *Store, c ManagementRouteConfig) (*ManagementRoute, error) {
	if s == nil || c.Administrators == nil || c.Connectors == nil || c.Administrators.Profile() != pki.Administrator || c.Connectors.Profile() != pki.Connector || c.Administrators.DeploymentID() != c.Connectors.DeploymentID() || c.Administrators.IssuerID() == c.Connectors.IssuerID() || c.Administrators.IssuerFingerprint() == c.Connectors.IssuerFingerprint() || !validID(c.ResourceID) || !validID(c.ConnectorID) || c.Revision < 1 || c.Port < 1 || c.Port > 65535 {
		return nil, ErrInvalid
	}
	address, err := literal(c.Address)
	if err != nil || address != c.Address {
		return nil, ErrInvalid
	}
	if _, err := c.Connectors.Verify(c.ConnectorLeafDER, c.ConnectorID, time.Now()); err != nil {
		return nil, ErrDenied
	}
	c.ConnectorLeafDER = bytes.Clone(c.ConnectorLeafDER)
	data, err := json.Marshal(struct {
		Purpose, Deployment, AdminIssuer, AdminRoot, AdminCA, ConnectorIssuer, ConnectorRoot, ConnectorCA, ConnectorLeaf, Resource, Connector, Address string
		Revision                                                                                                                                       int64
		Port                                                                                                                                           int
	}{"portico-private-management-route-v1", c.Administrators.DeploymentID(), c.Administrators.IssuerID(), c.Administrators.RootFingerprint(), c.Administrators.IssuerFingerprint(), c.Connectors.IssuerID(), c.Connectors.RootFingerprint(), c.Connectors.IssuerFingerprint(), pki.Hash(c.ConnectorLeafDER), c.ResourceID, c.ConnectorID, c.Address, c.Revision, c.Port})
	if err != nil {
		return nil, ErrInvalid
	}
	return &ManagementRoute{store: s, config: c, hash: pki.Hash(data)}, nil
}

// Check requires the actual end-to-end administrator TLS connection. Neither
// the configured connector nor a forwarded username can supply that identity.
func (m *ManagementRoute) Check(ctx context.Context, conn *tls.Conn) (ManagementAccess, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return ManagementAccess{}, ErrDenied
	}
	der, err := adminDER(ctx, conn)
	if err != nil {
		return ManagementAccess{}, ErrDenied
	}
	var result ManagementAccess
	err = m.store.Update(ctx, m.config.ConnectorID, func(t *Tx) error {
		var err error
		result, err = m.check(t, der)
		return err
	})
	if err != nil {
		return ManagementAccess{}, err
	}
	return result, nil
}

func (m *ManagementRoute) check(t *Tx, der []byte) (ManagementAccess, error) {
	var result ManagementAccess
	a, err := t.adminPeer(m.config.Administrators, der)
	if err != nil {
		return result, err
	}
	administrator, err := m.config.Administrators.Verify(der, a.device, t.now)
	if err != nil {
		return result, t.fail(ErrDenied)
	}
	connector, err := t.peer(m.config.Connectors, m.config.ConnectorLeafDER, false)
	if err != nil || connector.credential.PrincipalID != m.config.ConnectorID {
		return result, t.fail(ErrDenied)
	}
	// A dedicated connector may not have another enabled current resource,
	// even if that resource's hosting grant is temporarily disabled.
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision WHERE r.connector_id=? AND r.enabled=1 AND (r.id<>? OR r.revision<>? OR r.kind<>'management')`, m.config.ConnectorID, m.config.ResourceID, m.config.Revision).Scan(&count); err != nil {
		return result, t.fail(ErrStorage)
	}
	if count != 0 {
		return result, t.fail(ErrDenied)
	}
	now := t.now.UnixNano()
	rows, err := t.tx.QueryContext(t.ctx, `SELECT r.id,r.revision,r.name,r.connector_id,k.name,r.address,r.port,r.protocol,g.id,h.id,min(d.not_after,g.valid_until,h.valid_until)
 FROM resources r JOIN resource_heads rh ON rh.id=r.id AND rh.revision=r.revision
 JOIN connectors k ON k.id=r.connector_id
 JOIN grants g ON g.resource_id=r.id AND g.revision=r.revision
 JOIN devices d ON d.id=g.device_id AND d.user_id=g.user_id JOIN users u ON u.id=d.user_id
 JOIN host_bindings h ON h.resource_id=r.id AND h.revision=r.revision AND h.connector_id=r.connector_id
 WHERE r.id=? AND r.revision=? AND r.connector_id=? AND r.kind='management' AND r.enabled=1 AND r.address=? AND r.port=? AND r.protocol='tcp'
 AND k.enabled=1 AND d.id=? AND u.id=? AND d.enabled=1 AND u.enabled=1 AND d.not_after>?
 AND g.enabled=1 AND h.enabled=1 AND g.valid_from<=? AND g.valid_until>? AND h.valid_from<=? AND h.valid_until>? LIMIT 2`, m.config.ResourceID, m.config.Revision, m.config.ConnectorID, m.config.Address, m.config.Port, a.device, a.user, now, now, now, now, now)
	if err != nil {
		return result, t.fail(ErrStorage)
	}
	var bound int64
	if !rows.Next() || rows.Scan(&result.Resource.ID, &result.Resource.Revision, &result.Resource.Name, &result.Resource.ConnectorID, &result.Resource.ConnectorName, &result.Resource.Address, &result.Resource.Port, &result.Resource.Protocol, &result.GrantID, &result.BindingID, &bound) != nil {
		_ = rows.Close()
		return ManagementAccess{}, t.fail(ErrDenied)
	}
	ambiguous, readErr := rows.Next(), rows.Err()
	closeErr := rows.Close()
	if ambiguous || readErr != nil || closeErr != nil {
		return ManagementAccess{}, t.fail(ErrDenied)
	}
	until := time.Unix(0, bound).UTC()
	for _, end := range []time.Time{administrator.NotAfter, connector.credential.NotAfter} {
		if end.Before(until) {
			until = end
		}
	}
	if !until.After(t.now) {
		return ManagementAccess{}, t.fail(ErrDenied)
	}
	result.Version, result.DeviceID, result.UserID, result.CertificateFingerprint = 1, a.device, a.user, a.hash
	result.Resource.Until, result.ConnectorCertificateID = until, connector.certificateID
	result.RouteFingerprint, result.CheckedAt = m.hash, t.now
	result.PolicyRevision, err = t.policyRevision()
	if err != nil {
		return ManagementAccess{}, err
	}
	return result, nil
}
