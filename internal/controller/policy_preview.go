package controller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/pki"
)

type ResourceDraft struct {
	Name, ConnectorID, Address, Protocol string
	Port                                 int
}
type GrantDraft struct {
	UserID, DeviceID, ResourceID string
	Revision                     int64
	From, Until                  time.Time
}
type HostingDraft struct {
	ConnectorID, ResourceID string
	Revision                int64
	From, Until             time.Time
}

// Exactly one draft is permitted. ResourceID/ExpectedRevision are only accepted
// for a revision; all new security IDs and enabled flags are chosen by the server.
type PolicyDraft struct {
	Resource         *ResourceDraft `json:",omitempty"`
	Grant            *GrantDraft    `json:",omitempty"`
	Hosting          *HostingDraft  `json:",omitempty"`
	ResourceID       string         `json:",omitempty"`
	ExpectedRevision int64          `json:",omitempty"`
}
type PolicyPreview struct {
	ID, Digest, Kind, UserID, UserName, DeviceID, DeviceName string
	Resource                                                 ResourceAccess
	Previous                                                 *ResourceAccess `json:",omitempty"`
	From, Until, ExpiresAt                                   time.Time
	PolicyRevision                                           int64
}
type policyChange struct {
	Resource         *Resource
	Grant            *Grant
	Hosting          *HostBinding
	ExpectedRevision int64
}

func (p *PolicyEngine) resource(t *Tx, id string, revision int64) (ResourceAccess, error) {
	var r ResourceAccess
	if !validID(id) || revision < 1 {
		return r, t.fail(ErrInvalid)
	}
	e := t.tx.QueryRowContext(t.ctx, `SELECT r.id,r.revision,r.name,r.connector_id,k.name,r.address,r.port,r.protocol FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision JOIN connectors k ON k.id=r.connector_id WHERE r.id=? AND r.revision=? AND r.enabled=1 AND r.kind='application' AND k.enabled=1`, id, revision).Scan(&r.ID, &r.Revision, &r.Name, &r.ConnectorID, &r.ConnectorName, &r.Address, &r.Port, &r.Protocol)
	if e != nil || r.Protocol != "tcp" || !p.destination(r.Address) {
		return r, t.fail(ErrDenied)
	}
	return r, nil
}

func (p *PolicyEngine) prepare(t *Tx, id string, d PolicyDraft) (policyChange, PolicyPreview, error) {
	var change policyChange
	v := PolicyPreview{ID: id, ExpiresAt: t.now.Add(5 * time.Minute)}
	n := 0
	for _, has := range []bool{d.Resource != nil, d.Grant != nil, d.Hosting != nil} {
		if has {
			n++
		}
	}
	if n != 1 || (d.Resource == nil && (d.ResourceID != "" || d.ExpectedRevision != 0)) {
		return change, v, t.fail(ErrInvalid)
	}
	if d.Resource != nil {
		r := Resource{ID: NewID(), Revision: 1, Name: d.Resource.Name, ConnectorID: d.Resource.ConnectorID, Kind: "application", Address: d.Resource.Address, Port: d.Resource.Port, Protocol: d.Resource.Protocol, Enabled: true}
		address, e := validResource(r)
		if e != nil || !p.destination(address) {
			return change, v, t.fail(ErrDenied)
		}
		r.Address = address
		if d.ResourceID != "" {
			old, e := p.resource(t, d.ResourceID, d.ExpectedRevision)
			if e != nil {
				return change, v, e
			}
			v.Previous = &old
			r.ID = d.ResourceID
			r.Revision = d.ExpectedRevision + 1
			change.ExpectedRevision = d.ExpectedRevision
		} else if d.ExpectedRevision != 0 {
			return change, v, t.fail(ErrInvalid)
		}
		var connectorName string
		if t.tx.QueryRowContext(t.ctx, "SELECT name FROM connectors WHERE id=? AND enabled=1", r.ConnectorID).Scan(&connectorName) != nil {
			return change, v, t.fail(ErrDenied)
		}
		change.Resource = &r
		v.Kind = "create-resource"
		if v.Previous != nil {
			v.Kind = "revise-resource"
		}
		v.Resource = ResourceAccess{ID: r.ID, Revision: r.Revision, Name: r.Name, ConnectorID: r.ConnectorID, ConnectorName: connectorName, Address: r.Address, Port: r.Port, Protocol: r.Protocol}
	} else if d.Grant != nil {
		g := d.Grant
		if !validID(g.UserID) || !validID(g.DeviceID) || !interval(g.From, g.Until) || !g.Until.After(t.now) {
			return change, v, t.fail(ErrInvalid)
		}
		r, e := p.resource(t, g.ResourceID, g.Revision)
		if e != nil {
			return change, v, e
		}
		v.Resource = r
		var deviceUntil int64
		if t.tx.QueryRowContext(t.ctx, `SELECT u.name,d.name,d.not_after FROM users u JOIN devices d ON d.user_id=u.id WHERE u.id=? AND d.id=? AND u.enabled=1 AND d.enabled=1 AND EXISTS(SELECT 1 FROM enrollments e JOIN certificates c ON c.id=e.certificate_id WHERE e.device_id=d.id AND e.state='active' AND c.issuer_id=? AND c.revoked=0 AND c.not_before<=? AND c.not_after>?)`, g.UserID, g.DeviceID, p.config.DeviceTrust.IssuerID(), t.now.UnixNano(), t.now.UnixNano()).Scan(&v.UserName, &v.DeviceName, &deviceUntil) != nil || g.Until.UnixNano() > deviceUntil {
			return change, v, t.fail(ErrDenied)
		}
		var overlapping int
		if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM grants WHERE device_id=? AND resource_id=? AND revision=? AND enabled=1 AND valid_from<? AND valid_until>?", g.DeviceID, g.ResourceID, g.Revision, g.Until.UnixNano(), g.From.UnixNano()).Scan(&overlapping) != nil || overlapping != 0 {
			return change, v, t.fail(ErrDenied)
		}
		change.Grant = &Grant{ID: NewID(), UserID: g.UserID, DeviceID: g.DeviceID, ResourceID: g.ResourceID, ApprovalID: id, Revision: g.Revision, Enabled: true, From: g.From, Until: g.Until}
		v.Kind = "grant"
		v.UserID = g.UserID
		v.DeviceID = g.DeviceID
		v.From = g.From
		v.Until = g.Until
	} else {
		h := d.Hosting
		if !validID(h.ConnectorID) || !interval(h.From, h.Until) || !h.Until.After(t.now) {
			return change, v, t.fail(ErrInvalid)
		}
		r, e := p.resource(t, h.ResourceID, h.Revision)
		if e != nil {
			return change, v, e
		}
		if r.ConnectorID != h.ConnectorID {
			return change, v, t.fail(ErrDenied)
		}
		var count int
		if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM host_bindings WHERE connector_id=? AND resource_id=? AND revision=? AND enabled=1 AND valid_from<? AND valid_until>?", h.ConnectorID, h.ResourceID, h.Revision, h.Until.UnixNano(), h.From.UnixNano()).Scan(&count) != nil || count != 0 {
			return change, v, t.fail(ErrDenied)
		}
		change.Hosting = &HostBinding{ID: NewID(), ConnectorID: h.ConnectorID, ResourceID: h.ResourceID, Revision: h.Revision, Enabled: true, From: h.From, Until: h.Until}
		v.Kind = "host"
		v.Resource = r
		v.From = h.From
		v.Until = h.Until
	}
	gen, e := t.policyRevision()
	if e != nil {
		return change, v, e
	}
	v.PolicyRevision = gen
	return change, v, nil
}

func previewHash(operation, display []byte) string {
	return pki.Hash(append(append([]byte(nil), operation...), display...))
}

func (p *PolicyEngine) Preview(ctx context.Context, c *tls.Conn, trust *pki.Trust, d PolicyDraft) (PolicyPreview, error) {
	der, e := adminDER(ctx, c)
	if e != nil {
		return PolicyPreview{}, ErrDenied
	}
	var result PolicyPreview
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		admin, e := t.adminPeer(trust, der)
		if e != nil {
			return e
		}
		t.actor = admin.user
		if e = t.exec("DELETE FROM policy_previews WHERE expires_at<=? OR state='used'", t.now.UnixNano()); e != nil {
			return e
		}
		var count int
		if t.tx.QueryRowContext(ctx, "SELECT count(*) FROM policy_previews WHERE device_id=?", admin.device).Scan(&count) != nil || count >= 16 {
			return t.fail(ErrDenied)
		}
		change, view, e := p.prepare(t, NewID(), d)
		if e != nil {
			return e
		}
		op, e := json.Marshal(change)
		if e != nil {
			return t.fail(ErrInvalid)
		}
		display, e := json.Marshal(view)
		if e != nil {
			return t.fail(ErrInvalid)
		}
		if e = t.exec("INSERT INTO policy_previews VALUES(?,?,?,?,?,?,?,?,?,'pending')", view.ID, admin.device, admin.user, admin.hash, view.PolicyRevision, p.hash, op, display, view.ExpiresAt.UnixNano()); e != nil {
			return e
		}
		view.Digest = previewHash(op, display)
		result = view
		return t.event("policy.preview", view.ID)
	})
	if e != nil {
		return PolicyPreview{}, e
	}
	return result, nil
}

func (p *PolicyEngine) preview(t *Tx, admin adminPeer, id, hash string) (policyChange, error) {
	var change policyChange
	var op, display []byte
	var revision int64
	if !validID(id) || !digest(hash) {
		return change, t.fail(ErrInvalid)
	}
	e := t.tx.QueryRowContext(t.ctx, `SELECT operation_json,display_json,policy_revision FROM policy_previews WHERE id=? AND device_id=? AND user_id=? AND certificate_sha256=? AND config_sha256=? AND state='pending' AND expires_at>?`, id, admin.device, admin.user, admin.hash, p.hash, t.now.UnixNano()).Scan(&op, &display, &revision)
	if e != nil || len(op) > 16384 || len(display) > 16384 || previewHash(op, display) != hash {
		return change, t.fail(ErrDenied)
	}
	current, e := t.policyRevision()
	if e != nil {
		return change, e
	}
	if revision != current || json.Unmarshal(op, &change) != nil {
		return change, t.fail(ErrDenied)
	}
	return change, nil
}

func (p *PolicyEngine) BeginPolicyApproval(ctx context.Context, c *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id, hash string) (AdminChallenge, error) {
	der, e := adminDER(ctx, c)
	if e != nil {
		return AdminChallenge{}, ErrDenied
	}
	var result AdminChallenge
	e = p.store.Update(ctx, NewID(), func(t *Tx) error {
		admin, e := t.adminPeer(trust, der)
		if e != nil {
			return e
		}
		t.actor = admin.user
		if _, e = p.preview(t, admin, id, hash); e != nil {
			return e
		}
		var tested int
		if t.tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_factors WHERE user_id=? AND enabled=1 AND tested=1", admin.user).Scan(&tested) != nil || tested < 2 {
			return t.fail(ErrDenied)
		}
		result, e = t.stageAdmin(admin, v, AdminOperation{Kind: "apply-policy", TargetID: id, PolicyHash: hash}, false)
		return e
	})
	if e != nil {
		return AdminChallenge{}, e
	}
	return result, nil
}

func (p *PolicyEngine) FinishPolicyApproval(ctx context.Context, c *tls.Conn, trust *pki.Trust, v *adminauth.Verifier, id string, response []byte) error {
	_, e := p.store.finishAdminOperation(ctx, c, trust, v, id, response, func(t *Tx, admin adminPeer, op AdminOperation) error {
		change, e := p.preview(t, admin, op.TargetID, op.PolicyHash)
		if e != nil {
			return e
		}
		if change.Resource != nil {
			if !p.destination(change.Resource.Address) {
				return t.fail(ErrDenied)
			}
			if change.ExpectedRevision == 0 {
				e = t.AddResource(*change.Resource)
			} else {
				e = t.ReviseResource(change.ExpectedRevision, *change.Resource)
			}
		} else if change.Grant != nil {
			if !change.Grant.Until.After(t.now) {
				return t.fail(ErrDenied)
			}
			e = t.AddGrant(*change.Grant)
		} else if change.Hosting != nil {
			if !change.Hosting.Until.After(t.now) {
				return t.fail(ErrDenied)
			}
			e = t.AddHostBinding(*change.Hosting)
		} else {
			return t.fail(ErrDenied)
		}
		if e != nil {
			return e
		}
		if e = t.exec("UPDATE policy_previews SET state='used' WHERE id=?", op.TargetID); e != nil {
			return e
		}
		return t.event("policy.apply", op.TargetID)
	})
	return e
}
