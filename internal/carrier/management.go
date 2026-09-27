package carrier

import (
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/pki"
)

// ManagementConfig defines a separate relay instance. It cannot admit ordinary
// device certificates or pair another connector. Admission must verify current
// administrator authority and the exact management resource grant, and current
// ownership of the one configured connector. The opaque stream still needs its
// independent end-to-end authentication and destination authorization.
type ManagementConfig struct {
	ServerIdentity                             tls.Certificate
	Administrators, Connectors                 *pki.Trust
	ConnectorID                                string
	Admit                                      func(context.Context, pki.Credential, []byte) error
	MaxConnections, MaxStreams, MaxPeerStreams int
	HelloTimeout, PairTimeout, MaxLifetime     time.Duration
}

func NewManagement(c ManagementConfig) (*Relay, error) {
	if c.Administrators == nil || c.Connectors == nil || c.Administrators.Profile() != pki.Administrator || c.Administrators.IssuerID() == c.Connectors.IssuerID() || !pki.ValidID(c.ConnectorID) || c.MaxConnections > 16 || c.MaxStreams > 32 || c.MaxPeerStreams > 8 || c.MaxLifetime > 5*time.Second {
		return nil, ErrRejected
	}
	return newRelay(Config{ServerIdentity: c.ServerIdentity, Devices: c.Administrators, Connectors: c.Connectors, Admit: c.Admit, MaxConnections: c.MaxConnections, MaxStreams: c.MaxStreams, MaxPeerStreams: c.MaxPeerStreams, HelloTimeout: c.HelloTimeout, PairTimeout: c.PairTimeout, MaxLifetime: c.MaxLifetime}, pki.Administrator, c.ConnectorID)
}
