package controller

import (
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/pki"
)

// Inspection identifies exact registered certificates, not caller-supplied DER
// or a claim that a client owns either key. It never creates a session or permit.
type AccessInspectionRequest struct {
	DeviceCertificateID, ConnectorCertificateID, ResourceID string
	Revision, PolicyRevision                                int64
}

type AccessInspection struct {
	Version                                int
	Request                                AccessInspectionRequest
	PolicyRevision                         int64
	ObservedAt                             time.Time
	Allowed                                bool
	Reason                                 string
	UserID, UserName, DeviceID, DeviceName string
	ConnectorID                            string
	Resource                               *ResourceAccess `json:",omitempty"`
	GrantID, HostBindingID                 string
}

func (t policyReader) certificatePeer(trust *pki.Trust, id string) (peer, error) {
	var der []byte
	if err := t.tx.QueryRowContext(t.ctx, `SELECT e.certificate_der FROM certificates c JOIN enrollments e ON e.certificate_id=c.id WHERE c.id=? AND c.issuer_id=? AND c.profile=?`, id, trust.IssuerID(), string(trust.Profile())).Scan(&der); err != nil {
		return peer{}, policyReadError(err)
	}
	if len(der) == 0 || len(der) > pki.MaxDER {
		return peer{}, ErrIntegrity
	}
	v, err := t.peer(trust, der, false)
	if err != nil {
		return peer{}, err
	}
	if v.certificateID != id {
		return peer{}, ErrIntegrity
	}
	return v, nil
}

// InspectAccess runs the actual certificate, exact grant/hosting and quota
// checks in one authenticated snapshot, without the Authorize write path.
// A positive observation is neither a proof of possession nor a transport
// capability. Every later connection still goes through live authorization.
func (p *PolicyEngine) InspectAccess(ctx context.Context, conn *tls.Conn, trust *pki.Trust, request AccessInspectionRequest) (AccessInspection, error) {
	if !validID(request.DeviceCertificateID) || !validID(request.ConnectorCertificateID) || !validID(request.ResourceID) || request.Revision < 1 || request.PolicyRevision < 0 {
		return AccessInspection{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	der, err := adminDER(ctx, conn)
	if err != nil {
		return AccessInspection{}, err
	}
	var result AccessInspection
	err = p.store.Update(ctx, NewID(), func(tx *Tx) error {
		if _, err := tx.adminPeer(trust, der); err != nil {
			return err
		}
		revision, err := tx.policyRevision()
		if err != nil {
			return err
		}
		if request.PolicyRevision != 0 && request.PolicyRevision != revision {
			return tx.fail(ErrConflict)
		}
		result = AccessInspection{Version: 1, Request: request, PolicyRevision: revision, ObservedAt: tx.now}
		reader := tx.readPolicy()
		denied := func(err error, reason string) error {
			if err == ErrDenied {
				result.Reason = reason
				return nil
			}
			return tx.fail(err)
		}
		device, err := reader.certificatePeer(p.config.DeviceTrust, request.DeviceCertificateID)
		if err != nil {
			return denied(err, "device_identity_unavailable")
		}
		result.DeviceID = device.credential.PrincipalID
		if err := reader.tx.QueryRowContext(ctx, "SELECT u.id,u.name,d.name FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?", result.DeviceID).Scan(&result.UserID, &result.UserName, &result.DeviceName); err != nil {
			return tx.fail(policyReadError(err))
		}
		connector, err := reader.certificatePeer(p.config.ConnectorTrust, request.ConnectorCertificateID)
		if err != nil {
			return denied(err, "connector_identity_unavailable")
		}
		result.ConnectorID = connector.credential.PrincipalID
		match, err := p.readMatch(reader, device, connector, request.ResourceID, request.Revision)
		if err != nil {
			return denied(err, "no_unique_current_policy")
		}
		if err := p.readQuota(reader, result.DeviceID, result.ConnectorID); err != nil {
			return denied(err, "session_capacity_unavailable")
		}
		result.Allowed, result.Reason = true, "allowed_by_current_policy"
		result.Resource, result.GrantID, result.HostBindingID = &match.resource, match.grant, match.host
		return nil
	})
	if err != nil {
		return AccessInspection{}, err
	}
	return result, nil
}
