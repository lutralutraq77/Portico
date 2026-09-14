package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
)

// RegisterAdminDevice is a trusted local bootstrap/recovery primitive, never a
// remote endpoint. The owner supplies a separately issued administrator profile.
// It permits initial factor registration for at most ten minutes. Local owner
// authentication and physical independence qualification remain deployment work.
func (t *Tx) RegisterAdminDevice(user, device string, trust *pki.Trust, der []byte) error {
	if e := t.guard(validID(user) && validID(device) && trust != nil && trust.Profile() == pki.Administrator); e != nil {
		return e
	}
	c, e := trust.Verify(der, device, t.now)
	if e != nil {
		return t.fail(ErrDenied)
	}
	var count int
	if e = t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND u.id=? AND d.enabled=1 AND u.enabled=1 AND d.not_after>=?", device, user, c.NotAfter.UnixNano()).Scan(&count); e != nil || count != 1 {
		return t.fail(ErrDenied)
	}
	// An administrator intermediate must not be reused for ordinary identities.
	if e = t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM pki_bindings WHERE issuer_sha256=? OR deployment_id<>?", trust.IssuerFingerprint(), trust.DeploymentID()).Scan(&count); e != nil || count != 0 {
		return t.fail(ErrDenied)
	}
	if e = t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_devices WHERE deployment_id<>? OR (issuer_id=? AND (issuer_sha256<>? OR root_sha256<>?)) OR (issuer_sha256=? AND issuer_id<>?)", trust.DeploymentID(), trust.IssuerID(), trust.IssuerFingerprint(), trust.RootFingerprint(), trust.IssuerFingerprint(), trust.IssuerID()).Scan(&count); e != nil || count != 0 {
		return t.fail(ErrDenied)
	}
	if e = t.exec("INSERT INTO admin_devices VALUES(?,?,?,?,?,?,?,?,1,?)", device, user, trust.DeploymentID(), trust.IssuerID(), trust.RootFingerprint(), trust.IssuerFingerprint(), pki.Hash(der), bytes.Clone(der), t.now.Add(10*time.Minute).UnixNano()); e != nil {
		return e
	}
	return t.event("admin.device.register", device)
}

type adminPeer struct {
	device, user, hash string
	bootstrapUntil     int64
}

func (t *Tx) adminPeer(trust *pki.Trust, der []byte) (adminPeer, error) {
	var p adminPeer
	if trust == nil || trust.Profile() != pki.Administrator {
		return p, t.fail(ErrDenied)
	}
	p.hash = pki.Hash(der)
	e := t.tx.QueryRowContext(t.ctx, `SELECT a.device_id,a.user_id,a.bootstrap_until FROM admin_devices a JOIN devices d ON d.id=a.device_id JOIN users u ON u.id=a.user_id WHERE a.leaf_sha256=? AND a.deployment_id=? AND a.issuer_id=? AND a.root_sha256=? AND a.issuer_sha256=? AND a.enabled=1 AND d.enabled=1 AND u.enabled=1 AND d.not_after>?`, p.hash, trust.DeploymentID(), trust.IssuerID(), trust.RootFingerprint(), trust.IssuerFingerprint(), t.now.UnixNano()).Scan(&p.device, &p.user, &p.bootstrapUntil)
	if e != nil {
		return p, t.fail(ErrDenied)
	}
	if _, e = trust.Verify(der, p.device, t.now); e != nil {
		return p, t.fail(ErrDenied)
	}
	return p, nil
}

func (s *Store) AdminTLSConfig(identity tls.Certificate, trust *pki.Trust) (*tls.Config, error) {
	if trust == nil || trust.Profile() != pki.Administrator || len(identity.Certificate) == 0 || identity.PrivateKey == nil {
		return nil, ErrInvalid
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true}
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 {
			return ErrDenied
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Update(ctx, trust.IssuerID(), func(t *Tx) error { _, e := t.adminPeer(trust, state.PeerCertificates[0].Raw); return e })
	}
	return c, nil
}

func adminDER(ctx context.Context, conn *tls.Conn) ([]byte, error) {
	if conn == nil || conn.HandshakeContext(ctx) != nil {
		return nil, ErrDenied
	}
	s := conn.ConnectionState()
	if !s.HandshakeComplete || s.Version < tls.VersionTLS13 || len(s.PeerCertificates) == 0 {
		return nil, ErrDenied
	}
	return bytes.Clone(s.PeerCertificates[0].Raw), nil
}

type AdminOperation struct {
	Kind       string
	TargetID   string
	Invitation *InvitationSpec `json:",omitempty"`
	PolicyHash string          `json:",omitempty"`
}
type AdminChallenge struct {
	ID           string
	Registration *protocol.CredentialCreation  `json:",omitempty"`
	Approval     *protocol.CredentialAssertion `json:",omitempty"`
}
type AdminResult struct {
	InvitationID     string
	InvitationSecret string
	Registration     *AdminChallenge
}

func (t *Tx) adminUser(user string, testedOnly bool) (adminauth.User, error) {
	u := adminauth.User{ID: user}
	query := "SELECT credential_json FROM admin_factors WHERE user_id=? AND enabled=1"
	if testedOnly {
		query += " AND tested=1"
	}
	rows, e := t.tx.QueryContext(t.ctx, query+" ORDER BY id", user)
	if e != nil {
		return u, t.fail(ErrStorage)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var b []byte
		var c webauthn.Credential
		if rows.Scan(&b) != nil || len(b) > adminauth.MaxResponse || json.Unmarshal(b, &c) != nil {
			return u, t.fail(ErrIntegrity)
		}
		u.Credentials = append(u.Credentials, c)
	}
	if rows.Err() != nil {
		return u, t.fail(ErrStorage)
	}
	return u, nil
}

func (t *Tx) stageAdmin(p adminPeer, v *adminauth.Verifier, op AdminOperation, registration bool) (AdminChallenge, error) {
	var result AdminChallenge
	if v == nil || !validID(op.TargetID) {
		return result, t.fail(ErrInvalid)
	}
	if op.Kind != "invite" && op.Kind != "revoke-enrollment" && op.Kind != "apply-policy" && op.Kind != "register-factor" && op.Kind != "disable-factor" && op.Kind != "test-factor" && !(op.Kind == "bootstrap-factor" && registration) {
		return result, t.fail(ErrInvalid)
	}
	if (op.Kind == "invite") != (op.Invitation != nil) {
		return result, t.fail(ErrInvalid)
	}
	if (op.Kind == "apply-policy" && !digest(op.PolicyHash)) || (op.Kind != "apply-policy" && op.PolicyHash != "") {
		return result, t.fail(ErrInvalid)
	}
	if op.Invitation != nil && (op.Invitation.ID != op.TargetID || op.Invitation.Profile == pki.Administrator) {
		return result, t.fail(ErrDenied)
	}
	var pending int
	if e := t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_ceremonies WHERE device_id=? AND state='pending' AND expires_at>?", p.device, t.now.UnixNano()).Scan(&pending); e != nil || pending >= 16 {
		return result, t.fail(ErrDenied)
	}
	// Registration excludes all existing credentials. Only an explicit key test
	// can use an untested credential; other approvals require a prior key test.
	u, e := t.adminUser(p.user, !registration && op.Kind != "test-factor")
	if e != nil {
		return result, e
	}
	if op.Kind == "test-factor" || op.Kind == "disable-factor" {
		var target []byte
		if t.tx.QueryRowContext(t.ctx, "SELECT credential_id FROM admin_factors WHERE id=? AND user_id=? AND enabled=1", op.TargetID, p.user).Scan(&target) != nil {
			return result, t.fail(ErrDenied)
		}
		selected := u.Credentials[:0]
		for _, credential := range u.Credentials {
			if bytes.Equal(credential.ID, target) == (op.Kind == "test-factor") {
				selected = append(selected, credential)
			}
		}
		u.Credentials = selected
	}
	var generation int64
	if e = t.tx.QueryRowContext(t.ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&generation); e != nil {
		return result, t.fail(ErrStorage)
	}
	b, e := json.Marshal(op)
	if e != nil {
		return result, t.fail(ErrInvalid)
	}
	binding := adminauth.Binding{AdministratorID: p.user, DeviceCertificateHash: p.hash, OperationHash: pki.Hash(b), Revision: generation}
	var session adminauth.Session
	result.ID = NewID()
	if registration {
		result.Registration, session, e = v.BeginRegistration(u, binding)
	} else {
		result.Approval, session, e = v.BeginApproval(u, binding)
	}
	if e != nil {
		return AdminChallenge{}, t.fail(ErrDenied)
	}
	data, e := json.Marshal(session)
	if e != nil {
		return AdminChallenge{}, t.fail(ErrStorage)
	}
	if e = t.exec("INSERT INTO admin_ceremonies VALUES(?,?,?,?,?,'pending',?)", result.ID, p.device, p.user, data, b, session.ExpiresAt.UnixNano()); e != nil {
		return AdminChallenge{}, e
	}
	if e = t.event("admin.challenge", result.ID); e != nil {
		return AdminChallenge{}, e
	}
	return result, nil
}

// BeginInitialFactor requires both the actual registered administrator TLS key
// and the short local bootstrap window. It cannot replace factors after setup.
func (s *Store) BeginInitialFactor(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier) (AdminChallenge, error) {
	der, e := adminDER(ctx, conn)
	if e != nil {
		return AdminChallenge{}, e
	}
	var result AdminChallenge
	e = s.Update(ctx, NewID(), func(t *Tx) error {
		p, e := t.adminPeer(trust, der)
		if e != nil {
			return e
		}
		t.actor = p.user
		result, e = t.beginInitialFactor(p, v, NewID())
		return e
	})
	if e != nil {
		return AdminChallenge{}, e
	}
	return result, nil
}

func (t *Tx) beginInitialFactor(p adminPeer, v *adminauth.Verifier, id string) (AdminChallenge, error) {
	var count int
	if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_factors WHERE user_id=?", p.user).Scan(&count) != nil || count >= 2 || t.now.UnixNano() >= p.bootstrapUntil {
		return AdminChallenge{}, t.fail(ErrDenied)
	}
	return t.stageAdmin(p, v, AdminOperation{Kind: "bootstrap-factor", TargetID: id}, true)
}

func (t *Tx) beginAdmin(p adminPeer, v *adminauth.Verifier, op AdminOperation) (AdminChallenge, error) {
	var tested int
	if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM admin_factors WHERE user_id=? AND enabled=1 AND tested=1", p.user).Scan(&tested) != nil {
		return AdminChallenge{}, t.fail(ErrStorage)
	}
	if (op.Kind != "test-factor" && tested < 1) || ((invitationKind(op.Kind) || op.Kind == "apply-policy") && tested < 2) {
		return AdminChallenge{}, t.fail(ErrDenied)
	}
	return t.stageAdmin(p, v, op, false)
}

func (s *Store) BeginAdminOperation(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, op AdminOperation) (AdminChallenge, error) {
	der, e := adminDER(ctx, conn)
	if e != nil {
		return AdminChallenge{}, e
	}
	var result AdminChallenge
	e = s.Update(ctx, NewID(), func(t *Tx) error {
		p, e := t.adminPeer(trust, der)
		if e != nil {
			return e
		}
		t.actor = p.user
		result, e = t.beginAdmin(p, v, op)
		return e
	})
	if e != nil {
		return AdminChallenge{}, e
	}
	return result, nil
}

// FinishAdminOperation consumes the stored challenge, credential counter and
// exact operation in one transaction with its audit events. It rechecks TLS
// identity and the global policy generation immediately before the mutation.
func (s *Store) FinishAdminOperation(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, response []byte) (AdminResult, error) {
	return s.finishAdminOperation(ctx, conn, trust, v, id, response, adminFinishAny, nil)
}

type adminFinishScope uint8

const (
	adminFinishAny adminFinishScope = iota
	adminFinishFactor
	adminFinishInvitation
)

func (s *Store) finishAdminOperation(ctx context.Context, conn *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, response []byte, scope adminFinishScope, applyPolicy func(*Tx, adminPeer, AdminOperation) error) (AdminResult, error) {
	if v == nil || !validID(id) {
		return AdminResult{}, ErrInvalid
	}
	der, e := adminDER(ctx, conn)
	if e != nil {
		return AdminResult{}, e
	}
	var result AdminResult
	e = s.Update(ctx, NewID(), func(t *Tx) error {
		p, e := t.adminPeer(trust, der)
		if e != nil {
			return e
		}
		t.actor = p.user
		var sessionBytes, operationBytes []byte
		if e = t.tx.QueryRowContext(ctx, "SELECT session_json,operation_json FROM admin_ceremonies WHERE id=? AND device_id=? AND user_id=? AND state='pending' AND expires_at>?", id, p.device, p.user, t.now.UnixNano()).Scan(&sessionBytes, &operationBytes); e != nil {
			return t.fail(ErrDenied)
		}
		var session adminauth.Session
		var op AdminOperation
		if json.Unmarshal(sessionBytes, &session) != nil || json.Unmarshal(operationBytes, &op) != nil {
			return t.fail(ErrIntegrity)
		}
		if scope > adminFinishInvitation || (scope == adminFinishFactor && !factorKind(op.Kind)) || (scope == adminFinishInvitation && !invitationKind(op.Kind)) {
			return t.fail(ErrDenied)
		}
		if (applyPolicy != nil && op.Kind != "apply-policy") || (applyPolicy == nil && op.Kind == "apply-policy") {
			return t.fail(ErrDenied)
		}
		var generation int64
		if e = t.tx.QueryRowContext(ctx, "SELECT revision FROM policy_meta WHERE singleton=1").Scan(&generation); e != nil {
			return t.fail(ErrStorage)
		}
		binding := adminauth.Binding{AdministratorID: p.user, DeviceCertificateHash: p.hash, OperationHash: pki.Hash(operationBytes), Revision: generation}
		// Recheck tested state in the same transaction that commits the operation.
		u, e := t.adminUser(p.user, session.Kind != "registration" && op.Kind != "test-factor")
		if e != nil {
			return e
		}
		var credential *webauthn.Credential
		if session.Kind == "registration" {
			credential, e = v.VerifyRegistration(u, session, binding, response)
		} else {
			credential, e = v.VerifyApproval(u, session, binding, response)
		}
		if e != nil {
			return t.fail(ErrDenied)
		}
		public, e := json.Marshal(credential)
		if e != nil || len(public) > adminauth.MaxResponse {
			return t.fail(ErrStorage)
		}
		if e = t.exec("UPDATE admin_ceremonies SET state='used' WHERE id=?", id); e != nil {
			return e
		}
		if session.Kind == "registration" {
			if (op.Kind != "register-factor" && op.Kind != "bootstrap-factor") || len(u.Credentials) >= 8 {
				return t.fail(ErrDenied)
			}
			if op.Kind == "bootstrap-factor" {
				var count int
				if t.now.UnixNano() >= p.bootstrapUntil || t.tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_factors WHERE user_id=?", p.user).Scan(&count) != nil || count >= 2 {
					return t.fail(ErrDenied)
				}
			}
			if e = t.exec("INSERT INTO admin_factors VALUES(?,?,?,?,?,1,0)", op.TargetID, p.user, credential.ID, credential.PublicKey, public); e != nil {
				return e
			}
			return t.event("admin.factor.register", op.TargetID)
		}
		if e = t.exec("UPDATE admin_factors SET credential_json=?,tested=1 WHERE user_id=? AND credential_id=? AND enabled=1", public, p.user, credential.ID); e != nil {
			return e
		}
		if e = t.event("admin.approval", id); e != nil {
			return e
		}
		switch op.Kind {
		case "apply-policy":
			if applyPolicy == nil {
				return t.fail(ErrDenied)
			}
			return applyPolicy(t, p, op)
		case "invite":
			if op.Invitation == nil || op.TargetID != op.Invitation.ID {
				return t.fail(ErrDenied)
			}
			result.InvitationSecret, e = t.invite(*op.Invitation)
			result.InvitationID = op.TargetID
			return e
		case "revoke-enrollment":
			if _, e = t.reviewEnrollmentRevocation(p, op.TargetID); e != nil {
				return e
			}
			result.InvitationID = op.TargetID
			return t.RevokeEnrollment(op.TargetID)
		case "register-factor":
			challenge, e := t.stageAdmin(p, v, op, true)
			if e != nil {
				return e
			}
			result.Registration = &challenge
			return nil
		case "disable-factor":
			var targetID []byte
			if t.tx.QueryRowContext(ctx, "SELECT credential_id FROM admin_factors WHERE id=? AND user_id=? AND enabled=1", op.TargetID, p.user).Scan(&targetID) != nil || bytes.Equal(targetID, credential.ID) {
				return t.fail(ErrDenied)
			}
			if e = t.exec("UPDATE admin_factors SET enabled=0 WHERE id=?", op.TargetID); e != nil {
				return e
			}
			return t.event("admin.factor.disable", op.TargetID)
		case "test-factor":
			var factorID string
			if t.tx.QueryRowContext(ctx, "SELECT id FROM admin_factors WHERE credential_id=? AND user_id=?", credential.ID, p.user).Scan(&factorID) != nil || factorID != op.TargetID {
				return t.fail(ErrDenied)
			}
			return t.event("admin.factor.test", op.TargetID)
		default:
			return t.fail(ErrDenied)
		}
	})
	if e != nil {
		return AdminResult{}, e
	}
	return result, nil
}
