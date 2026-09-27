package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/pki"
)

type ManagementCarrierLimits struct {
	MaxConnections, MaxStreams, MaxPeerStreams int
	HelloTimeout, PairTimeout, MaxLifetime     time.Duration
}

// NewCarrier binds the separate management relay's live admission callback to
// this exact route. Every RPC authenticates its real TLS peer in carrier before
// invoking this callback; no HTTP or forwarded identity can call it. The caller
// still owns deployment isolation and the independent inner transport.
func (m *ManagementRoute) NewCarrier(identity tls.Certificate, limits ManagementCarrierLimits) (*carrier.Relay, error) {
	if m == nil {
		return nil, ErrInvalid
	}
	return carrier.NewManagement(carrier.ManagementConfig{ServerIdentity: identity, Administrators: m.config.Administrators, Connectors: m.config.Connectors, ConnectorID: m.config.ConnectorID, Admit: m.admitCarrier, MaxConnections: limits.MaxConnections, MaxStreams: limits.MaxStreams, MaxPeerStreams: limits.MaxPeerStreams, HelloTimeout: limits.HelloTimeout, PairTimeout: limits.PairTimeout, MaxLifetime: limits.MaxLifetime})
}

func (m *ManagementRoute) admitCarrier(ctx context.Context, authenticated pki.Credential, der []byte) error {
	if ctx == nil || ctx.Err() != nil || pki.Hash(der) != authenticated.LeafSHA256 {
		return ErrDenied
	}
	return m.store.Update(ctx, m.config.ConnectorID, func(t *Tx) error {
		switch authenticated.Profile {
		case pki.Administrator:
			actual, err := m.config.Administrators.VerifyPeer(der, t.now)
			if err != nil || actual != authenticated {
				return t.fail(ErrDenied)
			}
			_, err = m.check(t, der)
			return err
		case pki.Connector:
			if !bytes.Equal(der, m.config.ConnectorLeafDER) {
				return t.fail(ErrDenied)
			}
			peer, err := m.connector(t)
			if err != nil || peer.credential != authenticated {
				return t.fail(ErrDenied)
			}
			return nil
		default:
			return t.fail(ErrDenied)
		}
	})
}

func (m *ManagementRoute) connector(t *Tx) (peer, error) {
	connector, err := t.peer(m.config.Connectors, m.config.ConnectorLeafDER, false)
	if err != nil || connector.credential.PrincipalID != m.config.ConnectorID {
		return peer{}, t.fail(ErrDenied)
	}
	// A second enabled current resource is forbidden even when its hosting
	// binding is temporarily disabled. The one exact route needs one live host.
	var count int
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision WHERE r.connector_id=? AND r.enabled=1 AND (r.id<>? OR r.revision<>? OR r.kind<>'management')`, m.config.ConnectorID, m.config.ResourceID, m.config.Revision).Scan(&count); err != nil {
		return peer{}, t.fail(ErrStorage)
	}
	if count != 0 {
		return peer{}, t.fail(ErrDenied)
	}
	now := t.now.UnixNano()
	if err := t.tx.QueryRowContext(t.ctx, `SELECT count(*) FROM resources r JOIN resource_heads rh ON rh.id=r.id AND rh.revision=r.revision JOIN host_bindings h ON h.resource_id=r.id AND h.revision=r.revision AND h.connector_id=r.connector_id WHERE r.id=? AND r.revision=? AND r.connector_id=? AND r.kind='management' AND r.enabled=1 AND r.address=? AND r.port=? AND r.protocol='tcp' AND h.enabled=1 AND h.valid_from<=? AND h.valid_until>?`, m.config.ResourceID, m.config.Revision, m.config.ConnectorID, m.config.Address, m.config.Port, now, now).Scan(&count); err != nil {
		return peer{}, t.fail(ErrStorage)
	}
	if count != 1 {
		return peer{}, t.fail(ErrDenied)
	}
	return connector, nil
}
