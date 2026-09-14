package controller

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
)

// Only factor record identifiers and attested model metadata leave this read.
// Credential handles, keys, attestation bodies and ceremonies are omitted.
type DashboardFactor struct {
	ID, ModelID     string
	Enabled, Tested bool
}

func dashboardFactors(tx *Tx, request DashboardRequest, peer adminPeer) ([]DashboardFactor, string, error) {
	return dashboardRows(tx, request, "SELECT id,credential_json,enabled,tested FROM admin_factors WHERE id>? AND user_id=? ORDER BY id LIMIT ?", func(rows *sql.Rows) (DashboardFactor, string, error) {
		var result DashboardFactor
		var data []byte
		var metadata struct{ Authenticator struct{ AAGUID []byte } }
		if rows.Scan(&result.ID, &data, &result.Enabled, &result.Tested) != nil || len(data) > adminauth.MaxResponse || json.Unmarshal(data, &metadata) != nil {
			return result, "", ErrIntegrity
		}
		id, err := uuid.FromBytes(metadata.Authenticator.AAGUID)
		if err != nil || id == uuid.Nil {
			return result, "", ErrIntegrity
		}
		result.ModelID = id.String()
		return result, result.ID, nil
	}, peer.user)
}

type FactorRequest struct {
	Kind, FactorID string
	PolicyRevision int64
}

type FactorChallenge struct {
	Kind, FactorID string
	PolicyRevision int64
	ExpiresAt      time.Time
	Challenge      AdminChallenge
}

type FactorResult struct {
	Registration *AdminChallenge `json:",omitempty"`
}

func factorKind(kind string) bool {
	return kind == "bootstrap-factor" || kind == "register-factor" || kind == "test-factor" || kind == "disable-factor"
}

// BeginFactor binds the browser's displayed revision, actual administrator
// identity and exact operation in one transaction. New record IDs are server-owned.
func (s *Store) BeginFactor(ctx context.Context, conn *tls.Conn, trust *pki.Trust, verifier *adminauth.Verifier, request FactorRequest) (FactorChallenge, error) {
	creating := request.Kind == "bootstrap-factor" || request.Kind == "register-factor"
	if !factorKind(request.Kind) || request.PolicyRevision < 1 || (creating && request.FactorID != "") || (!creating && !validID(request.FactorID)) {
		return FactorChallenge{}, ErrInvalid
	}
	der, err := adminDER(ctx, conn)
	if err != nil {
		return FactorChallenge{}, err
	}
	var result FactorChallenge
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
		if revision != request.PolicyRevision {
			return tx.fail(ErrConflict)
		}
		id := request.FactorID
		if creating {
			id = NewID()
		}
		result = FactorChallenge{Kind: request.Kind, FactorID: id, PolicyRevision: revision}
		if request.Kind == "bootstrap-factor" {
			result.Challenge, err = tx.beginInitialFactor(peer, verifier, id)
		} else {
			result.Challenge, err = tx.beginAdmin(peer, verifier, AdminOperation{Kind: request.Kind, TargetID: id})
		}
		if err != nil {
			return err
		}
		var expires int64
		if tx.tx.QueryRowContext(tx.ctx, "SELECT expires_at FROM admin_ceremonies WHERE id=?", result.Challenge.ID).Scan(&expires) != nil {
			return tx.fail(ErrStorage)
		}
		result.ExpiresAt = time.Unix(0, expires).UTC()
		return nil
	})
	if err != nil {
		return FactorChallenge{}, err
	}
	return result, nil
}

func (s *Store) FinishFactor(ctx context.Context, conn *tls.Conn, trust *pki.Trust, verifier *adminauth.Verifier, id string, response []byte) (FactorResult, error) {
	result, err := s.finishAdminOperation(ctx, conn, trust, verifier, id, response, adminFinishFactor, nil)
	if err != nil {
		return FactorResult{}, err
	}
	return FactorResult{Registration: result.Registration}, nil
}
