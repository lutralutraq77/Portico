package controller

import (
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
)

type InvitationRequest struct {
	Kind, EnrollmentID, IssuerID, PrincipalID string
	Profile                                   pki.Profile
	ExpiresAt, NotAfter                       time.Time
	PolicyRevision                            int64
}

type InvitationReview struct {
	InvitationSpec
	PrincipalName, UserID, UserName, State string
}

type InvitationChallenge struct {
	Kind           string
	PolicyRevision int64
	ExpiresAt      time.Time
	Invitation     InvitationReview
	Challenge      AdminChallenge
}

// The secret is returned once, only after the hardware-approved transaction
// and its audit commit. Inventory and challenge responses never contain it.
type InvitationResult struct {
	ID     string
	Secret string `json:",omitempty"`
}

func invitationKind(kind string) bool { return kind == "invite" || kind == "revoke-enrollment" }

func (t *Tx) invitationNames(spec InvitationSpec, state string) (InvitationReview, error) {
	result := InvitationReview{InvitationSpec: spec, State: state}
	var err error
	switch spec.Profile {
	case pki.Device:
		err = t.tx.QueryRowContext(t.ctx, "SELECT d.name,u.id,u.name FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?", spec.PrincipalID).Scan(&result.PrincipalName, &result.UserID, &result.UserName)
	case pki.Connector:
		err = t.tx.QueryRowContext(t.ctx, "SELECT name FROM connectors WHERE id=?", spec.PrincipalID).Scan(&result.PrincipalName)
	default:
		return result, t.fail(ErrInvalid)
	}
	if err != nil {
		return result, t.fail(ErrDenied)
	}
	return result, nil
}

func (t *Tx) reviewEnrollmentRevocation(peer adminPeer, id string) (InvitationReview, error) {
	v, err := t.enrollment(id)
	if err != nil {
		return InvitationReview{}, err
	}
	if v.state == "revoked" || (v.profile == pki.Device && v.principal == peer.device) {
		return InvitationReview{}, t.fail(ErrDenied)
	}
	if v.profile == pki.Connector {
		var count int
		if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision WHERE r.connector_id=? AND r.kind='management' AND r.enabled=1", v.principal).Scan(&count) != nil || count != 0 {
			return InvitationReview{}, t.fail(ErrDenied)
		}
	}
	return t.invitationNames(InvitationSpec{ID: v.id, IssuerID: v.issuer, PrincipalID: v.principal, Profile: v.profile, ExpiresAt: time.Unix(0, v.expires).UTC(), NotAfter: time.Unix(0, v.until).UTC()}, v.state)
}

// BeginInvitation stages only the reviewed operation. It does not generate a
// secret, reserve enrollment authority, or call an issuer. Names and identities
// are resolved in the same revision-bound transaction as the native challenge.
func (s *Store) BeginInvitation(ctx context.Context, conn *tls.Conn, trust *pki.Trust, verifier *adminauth.Verifier, request InvitationRequest) (InvitationChallenge, error) {
	if !invitationKind(request.Kind) || request.PolicyRevision < 1 {
		return InvitationChallenge{}, ErrInvalid
	}
	creating := request.Kind == "invite"
	if (creating && (request.EnrollmentID != "" || !validID(request.IssuerID) || !validID(request.PrincipalID) || (request.Profile != pki.Device && request.Profile != pki.Connector))) ||
		(!creating && (!validID(request.EnrollmentID) || request.IssuerID != "" || request.PrincipalID != "" || request.Profile != "" || !request.ExpiresAt.IsZero() || !request.NotAfter.IsZero())) {
		return InvitationChallenge{}, ErrInvalid
	}
	der, err := adminDER(ctx, conn)
	if err != nil {
		return InvitationChallenge{}, err
	}
	var result InvitationChallenge
	err = s.Update(ctx, NewID(), func(tx *Tx) error {
		peer, err := tx.adminPeer(trust, der)
		if err != nil {
			return err
		}
		tx.actor = peer.user
		revision, err := tx.policyRevision()
		if err != nil {
			return err
		}
		if request.PolicyRevision != revision {
			return tx.fail(ErrConflict)
		}
		result = InvitationChallenge{Kind: request.Kind, PolicyRevision: revision}
		op := AdminOperation{Kind: request.Kind, TargetID: request.EnrollmentID}
		if creating {
			spec := InvitationSpec{ID: NewID(), IssuerID: request.IssuerID, PrincipalID: request.PrincipalID, Profile: request.Profile, ExpiresAt: request.ExpiresAt.UTC(), NotAfter: request.NotAfter.UTC()}
			if !interval(tx.now, spec.ExpiresAt) || spec.ExpiresAt.Sub(tx.now) > time.Hour || !interval(tx.now, spec.NotAfter) || !spec.NotAfter.Equal(spec.NotAfter.Truncate(time.Second)) {
				return tx.fail(ErrInvalid)
			}
			if err := tx.enrollmentAuthority(spec.IssuerID, spec.PrincipalID, spec.Profile, spec.NotAfter); err != nil {
				return err
			}
			result.Invitation, err = tx.invitationNames(spec, "pending-approval")
			op.TargetID, op.Invitation = spec.ID, &spec
		} else {
			result.Invitation, err = tx.reviewEnrollmentRevocation(peer, request.EnrollmentID)
		}
		if err != nil {
			return err
		}
		result.Challenge, err = tx.beginAdmin(peer, verifier, op)
		if err != nil {
			return err
		}
		var expiry int64
		if tx.tx.QueryRowContext(tx.ctx, "SELECT expires_at FROM admin_ceremonies WHERE id=?", result.Challenge.ID).Scan(&expiry) != nil {
			return tx.fail(ErrStorage)
		}
		result.ExpiresAt = time.Unix(0, expiry).UTC()
		return nil
	})
	if err != nil {
		return InvitationChallenge{}, err
	}
	return result, nil
}

func (s *Store) FinishInvitation(ctx context.Context, conn *tls.Conn, trust *pki.Trust, verifier *adminauth.Verifier, id string, response []byte) (InvitationResult, error) {
	result, err := s.finishAdminOperation(ctx, conn, trust, verifier, id, response, adminFinishInvitation, nil)
	if err != nil {
		return InvitationResult{}, err
	}
	return InvitationResult{ID: result.InvitationID, Secret: result.InvitationSecret}, nil
}
