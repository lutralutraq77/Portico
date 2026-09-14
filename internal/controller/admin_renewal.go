package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
)

// AdminRenewalSpec contains public material only. Renewal retains the exact
// current administrator key and cannot extend the user's/device's authority.
type AdminRenewalSpec struct {
	CSR      []byte
	NotAfter time.Time
}

type AdminRenewalPrepared struct {
	Version                int
	RenewalID              string
	CSRHash                string
	CurrentCertificateHash string
	NotAfter               time.Time
	PolicyRevision         int64
	Challenge              AdminChallenge
}

func (t *Tx) reviewAdminRenewal(p adminPeer, trust *pki.Trust, op AdminOperation) ([]byte, string, error) {
	if op.Kind != "renew-administrator" || !validID(op.TargetID) || op.Renewal == nil || op.Invitation != nil || op.PolicyHash != "" || trust == nil || trust.Profile() != pki.Administrator {
		return nil, "", t.fail(ErrInvalid)
	}
	csr, err := pki.ParseCSR(op.Renewal.CSR)
	if err != nil {
		return nil, "", t.fail(ErrDenied)
	}
	var old []byte
	var authority int64
	if t.tx.QueryRowContext(t.ctx, `SELECT a.certificate_der,d.not_after FROM admin_devices a JOIN devices d ON d.id=a.device_id WHERE a.device_id=? AND a.leaf_sha256=?`, p.device, p.hash).Scan(&old, &authority) != nil {
		return nil, "", t.fail(ErrDenied)
	}
	credential, err := trust.Verify(old, p.device, t.now)
	until := op.Renewal.NotAfter
	if err != nil || pki.Hash(csr.RawSubjectPublicKeyInfo) != credential.SPKISHA256 || !until.Equal(until.Truncate(time.Second)) || !until.After(credential.NotAfter) || until.After(t.now.Truncate(time.Second).Add(24*time.Hour)) || until.After(trust.NotAfter()) || until.UnixNano() > authority {
		return nil, "", t.fail(ErrDenied)
	}
	var factors, pending int
	if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_factors WHERE user_id=? AND enabled=1 AND tested=1", p.user).Scan(&factors) != nil || factors < 2 || t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_renewals WHERE device_id=? AND state IN ('approved','issuing','issued')", p.device).Scan(&pending) != nil || pending != 0 {
		return nil, "", t.fail(ErrDenied)
	}
	return old, credential.SPKISHA256, nil
}

func (s *Store) BeginAdminRenewal(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, spec AdminRenewalSpec) (AdminChallenge, error) {
	result, err := s.beginAdminRenewal(ctx, conn, trust, v, id, spec, 0)
	return result.Challenge, err
}

func (s *Store) beginAdminRenewal(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, spec AdminRenewalSpec, expectedRevision int64) (AdminRenewalPrepared, error) {
	if len(spec.CSR) == 0 || len(spec.CSR) > pki.MaxCSR || expectedRevision < 0 {
		return AdminRenewalPrepared{}, ErrInvalid
	}
	der, err := adminDER(ctx, conn)
	if err != nil {
		return AdminRenewalPrepared{}, err
	}
	spec.CSR = bytes.Clone(spec.CSR)
	op := AdminOperation{Kind: "renew-administrator", TargetID: id, Renewal: &spec}
	var result AdminRenewalPrepared
	err = s.Update(ctx, NewID(), func(t *Tx) error {
		peer, err := t.adminPeer(trust, der)
		if err != nil {
			return err
		}
		t.actor = peer.user
		if _, _, err = t.reviewAdminRenewal(peer, trust, op); err != nil {
			return err
		}
		revision, err := t.policyRevision()
		if err != nil {
			return err
		}
		if expectedRevision != 0 && expectedRevision != revision {
			return t.fail(ErrConflict)
		}
		result = AdminRenewalPrepared{Version: 1, RenewalID: id, CSRHash: pki.Hash(spec.CSR), CurrentCertificateHash: peer.hash, NotAfter: spec.NotAfter, PolicyRevision: revision}
		result.Challenge, err = t.beginAdmin(peer, v, op)
		return err
	})
	if err != nil {
		return AdminRenewalPrepared{}, err
	}
	return result, nil
}

// FinishAdminRenewal consumes one fresh, exact-operation hardware approval. It
// reserves one signing attempt; it neither calls an issuer nor replaces a leaf.
func (s *Store) FinishAdminRenewal(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, response []byte) (string, error) {
	result, err := s.finishAdminOperation(ctx, conn, trust, v, id, response, adminFinishRenewal, nil)
	return result.RenewalID, err
}

func (t *Tx) reserveAdminRenewal(peer adminPeer, trust *pki.Trust, op AdminOperation) error {
	old, spki, err := t.reviewAdminRenewal(peer, trust, op)
	if err != nil {
		return err
	}
	var revision int64
	if t.tx.QueryRowContext(t.ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&revision) != nil {
		return t.fail(ErrStorage)
	}
	if err = t.exec(`INSERT INTO admin_renewals(id,device_id,old_sha256,old_der,csr_der,spki_sha256,created_at,expires_at,not_after,policy_revision,state) VALUES(?,?,?,?,?,?,?,?,?,?,'approved')`, op.TargetID, peer.device, peer.hash, old, op.Renewal.CSR, spki, t.now.UnixNano(), t.now.Add(10*time.Minute).UnixNano(), op.Renewal.NotAfter.UnixNano(), revision); err != nil {
		return err
	}
	return t.event("admin.renewal.approve", op.TargetID)
}

type adminRenewal struct {
	id, device, oldHash, spki, state  string
	old, csr, der                     []byte
	created, expires, until, revision int64
}

func (t *Tx) adminRenewal(id string) (adminRenewal, error) {
	r := adminRenewal{id: id}
	if !validID(id) || t.tx.QueryRowContext(t.ctx, "SELECT device_id,old_sha256,old_der,csr_der,spki_sha256,created_at,expires_at,not_after,policy_revision,state,certificate_der FROM admin_renewals WHERE id=?", id).Scan(&r.device, &r.oldHash, &r.old, &r.csr, &r.spki, &r.created, &r.expires, &r.until, &r.revision, &r.state, &r.der) != nil {
		return r, t.fail(ErrDenied)
	}
	return r, nil
}

func (t *Tx) adminRenewalAuthority(trust *pki.Trust, r adminRenewal) error {
	if r.state == "revoked" || t.now.UnixNano() < r.created || t.now.UnixNano() >= r.expires {
		return t.fail(ErrDenied)
	}
	var revision int64
	if r.state != "active" && (t.tx.QueryRowContext(t.ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&revision) != nil || revision != r.revision) {
		return t.fail(ErrDenied)
	}
	der := r.old
	if r.state == "active" {
		der = r.der
	}
	peer, err := t.adminPeer(trust, der)
	if err != nil || peer.device != r.device || (r.state != "active" && peer.hash != r.oldHash) {
		return t.fail(ErrDenied)
	}
	var authority int64
	var factors int
	if t.tx.QueryRowContext(t.ctx, "SELECT not_after FROM devices WHERE id=? AND enabled=1", r.device).Scan(&authority) != nil || authority < r.until || time.Unix(0, r.until).After(trust.NotAfter()) || t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_factors WHERE user_id=? AND enabled=1 AND tested=1", peer.user).Scan(&factors) != nil || factors < 2 {
		return t.fail(ErrDenied)
	}
	return nil
}

// IssueAdminRenewal is a trusted registration-authority operation. The durable
// transition commits before the one permitted provider call. Ambiguous failures
// require public-result reconciliation; they never cause an automatic retry.
func (s *Store) IssueAdminRenewal(ctx context.Context, actor, id string, trust *pki.Trust, provider IssuanceProvider) error {
	if provider == nil {
		return ErrInvalid
	}
	var request IssuanceRequest
	err := s.Update(ctx, actor, func(t *Tx) error {
		r, err := t.adminRenewal(id)
		if err != nil {
			return err
		}
		if r.state != "approved" {
			return t.fail(ErrDenied)
		}
		if err = t.adminRenewalAuthority(trust, r); err != nil {
			return err
		}
		request = IssuanceRequest{AttemptID: r.id, DeploymentID: trust.DeploymentID(), IssuerID: trust.IssuerID(), PrincipalID: r.device, Profile: pki.Administrator, CSR: bytes.Clone(r.csr), NotBefore: time.Unix(0, r.created).UTC().Truncate(time.Second), NotAfter: time.Unix(0, r.until).UTC()}
		if err = t.exec("UPDATE admin_renewals SET state='issuing' WHERE id=?", id); err != nil {
			return err
		}
		return t.event("admin.renewal.issuing", id)
	})
	if err != nil {
		return err
	}
	der, err := provider.Issue(ctx, request)
	if err != nil {
		return ErrDenied
	}
	return s.ReconcileAdminRenewal(ctx, actor, id, trust, der)
}

// ReconcileAdminRenewal validates the exact public signing result. It grants
// no administrator access. A distinct TLS proof is required for activation.
func (s *Store) ReconcileAdminRenewal(ctx context.Context, actor, id string, trust *pki.Trust, der []byte) error {
	if len(der) == 0 || len(der) > pki.MaxDER {
		return ErrInvalid
	}
	der = bytes.Clone(der)
	return s.Update(ctx, actor, func(t *Tx) error {
		r, err := t.adminRenewal(id)
		if err != nil {
			return err
		}
		if err = t.adminRenewalAuthority(trust, r); err != nil {
			return err
		}
		if r.state == "issued" || r.state == "active" {
			if bytes.Equal(r.der, der) {
				return nil
			}
			return t.fail(ErrDenied)
		}
		if r.state != "issuing" {
			return t.fail(ErrDenied)
		}
		credential, err := trust.Verify(der, r.device, t.now)
		if err != nil || credential.SPKISHA256 != r.spki || !credential.NotBefore.Equal(time.Unix(0, r.created).Truncate(time.Second)) || !credential.NotAfter.Equal(time.Unix(0, r.until)) || credential.LeafSHA256 == r.oldHash {
			return t.fail(ErrDenied)
		}
		if err = t.exec("UPDATE admin_renewals SET state='issued',leaf_sha256=?,certificate_der=? WHERE id=?", credential.LeafSHA256, der, id); err != nil {
			return err
		}
		return t.event("admin.renewal.issued", id)
	})
}

// AdminRenewalCertificate returns the public candidate only to the still-live
// old administrator connection which approved it. It does not activate it.
func (s *Store) AdminRenewalCertificate(ctx context.Context, conn *tls.Conn, trust *pki.Trust, id string) ([]byte, error) {
	der, err := adminDER(ctx, conn)
	if err != nil {
		return nil, err
	}
	var result []byte
	err = s.Update(ctx, NewID(), func(t *Tx) error {
		peer, err := t.adminPeer(trust, der)
		if err != nil {
			return err
		}
		r, err := t.adminRenewal(id)
		if err != nil {
			return err
		}
		if r.state != "issued" || peer.device != r.device || peer.hash != r.oldHash {
			return t.fail(ErrDenied)
		}
		if err = t.adminRenewalAuthority(trust, r); err != nil {
			return err
		}
		result = bytes.Clone(r.der)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (t *Tx) adminRenewalCandidate(trust *pki.Trust, der []byte) (adminRenewal, error) {
	var id string
	if t.tx.QueryRowContext(t.ctx, "SELECT id FROM admin_renewals WHERE leaf_sha256=? AND state IN ('issued','active')", pki.Hash(der)).Scan(&id) != nil {
		return adminRenewal{}, t.fail(ErrDenied)
	}
	r, err := t.adminRenewal(id)
	if err != nil {
		return r, err
	}
	if err = t.adminRenewalAuthority(trust, r); err != nil {
		return r, err
	}
	credential, err := trust.Verify(der, r.device, t.now)
	if err != nil || credential.SPKISHA256 != r.spki || !bytes.Equal(r.der, der) {
		return r, t.fail(ErrDenied)
	}
	return r, nil
}

// AdminRenewalTLSConfig belongs on a separate activation-only listener. The
// normal AdminTLSConfig continues rejecting unactivated replacement leaves.
func (s *Store) AdminRenewalTLSConfig(identity tls.Certificate, trust *pki.Trust) (*tls.Config, error) {
	c, err := s.AdminTLSConfig(identity, trust)
	if err != nil {
		return nil, err
	}
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 {
			return ErrDenied
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Update(ctx, trust.IssuerID(), func(t *Tx) error {
			_, err := t.adminRenewalCandidate(trust, state.PeerCertificates[0].Raw)
			return err
		})
	}
	return c, nil
}

func (s *Store) ActivateAdminRenewal(ctx context.Context, conn *tls.Conn, trust *pki.Trust, id string) error {
	der, err := adminDER(ctx, conn)
	if err != nil {
		return err
	}
	return s.Update(ctx, NewID(), func(t *Tx) error {
		r, err := t.adminRenewalCandidate(trust, der)
		if err != nil {
			return err
		}
		if r.id != id {
			return t.fail(ErrDenied)
		}
		if r.state == "active" {
			return nil
		}
		if t.tx.QueryRowContext(t.ctx, "SELECT user_id FROM admin_devices WHERE device_id=?", r.device).Scan(&t.actor) != nil {
			return t.fail(ErrDenied)
		}
		if err = t.exec("UPDATE admin_devices SET leaf_sha256=?,certificate_der=?,bootstrap_until=0 WHERE device_id=? AND leaf_sha256=?", pki.Hash(der), der, r.device, r.oldHash); err != nil {
			return err
		}
		if err = t.exec("UPDATE admin_renewals SET state='active' WHERE id=?", id); err != nil {
			return err
		}
		if err = t.exec("DELETE FROM admin_ceremonies WHERE device_id=?", r.device); err != nil {
			return err
		}
		return t.event("admin.renewal.activate", id)
	})
}

// RevokeAdminRenewal is trusted local reconciliation, not an unauthenticated
// escape hatch. Revoking an active history entry does not change its live leaf.
func (t *Tx) RevokeAdminRenewal(id string) error {
	r, err := t.adminRenewal(id)
	if err != nil || r.state == "revoked" {
		return err
	}
	if r.state == "active" {
		return t.fail(ErrDenied)
	}
	if err = t.exec("UPDATE admin_renewals SET state='revoked' WHERE id=?", id); err != nil {
		return err
	}
	return t.event("admin.renewal.revoke", id)
}
