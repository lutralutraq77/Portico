package controller

import (
	"strings"
	"time"
)

// Lifecycle drafts create records, rename metadata or revoke access. They never
// issue credentials, return invitations, re-enable tombstones or add permissions.
type LifecycleDraft struct {
	Kind           string
	PolicyRevision int64
	TargetID       string    `json:",omitempty"`
	Name           string    `json:",omitempty"`
	UserID         string    `json:",omitempty"`
	Platform       string    `json:",omitempty"`
	NotAfter       time.Time `json:",omitzero"`
}

type LifecycleTarget struct {
	Entity, ID, Name, UserID, UserName, Platform, Version string
	Enabled                                               bool
	NotAfter                                              time.Time
}

type lifecycleChange struct {
	Kind         string
	Target       LifecycleTarget
	PreviousName string
}

func lifecycleKind(kind string) (action, entity string, ok bool) {
	action, entity, ok = strings.Cut(kind, "-")
	ok = ok && (action == "create" || action == "rename" || action == "disable") && (entity == "user" || entity == "device" || entity == "connector")
	return
}

func (p *PolicyEngine) lifecycleTarget(t *Tx, admin adminPeer, kind, id string) (LifecycleTarget, error) {
	action, entity, ok := lifecycleKind(kind)
	result := LifecycleTarget{Entity: entity, ID: id}
	if !ok || action == "create" || !validID(id) {
		return result, t.fail(ErrInvalid)
	}
	var err error
	switch entity {
	case "user":
		err = t.tx.QueryRowContext(t.ctx, "SELECT name,enabled FROM users WHERE id=?", id).Scan(&result.Name, &result.Enabled)
	case "device":
		var expiry int64
		err = t.tx.QueryRowContext(t.ctx, "SELECT d.name,d.user_id,u.name,d.platform,d.enabled,d.not_after FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?", id).Scan(&result.Name, &result.UserID, &result.UserName, &result.Platform, &result.Enabled, &expiry)
		result.NotAfter = time.Unix(0, expiry).UTC()
	case "connector":
		err = t.tx.QueryRowContext(t.ctx, "SELECT name,version,enabled FROM connectors WHERE id=?", id).Scan(&result.Name, &result.Version, &result.Enabled)
	}
	if err != nil || !result.Enabled {
		return result, t.fail(ErrDenied)
	}
	if action == "disable" {
		// The authenticated operator must retain a working administrator identity.
		if (entity == "user" && id == admin.user) || (entity == "device" && id == admin.device) {
			return result, t.fail(ErrDenied)
		}
		if entity == "connector" {
			var management int
			if t.tx.QueryRowContext(t.ctx, "SELECT count(*) FROM resources r JOIN resource_heads h ON h.id=r.id AND h.revision=r.revision WHERE r.connector_id=? AND r.kind='management' AND r.enabled=1", id).Scan(&management) != nil || management != 0 {
				return result, t.fail(ErrDenied)
			}
		}
	}
	return result, nil
}

func (p *PolicyEngine) prepareLifecycle(t *Tx, admin adminPeer, draft LifecycleDraft) (*lifecycleChange, *LifecycleTarget, string, error) {
	action, entity, ok := lifecycleKind(draft.Kind)
	revision, err := t.policyRevision()
	if err != nil {
		return nil, nil, "", err
	}
	if !ok || draft.PolicyRevision < 1 || draft.PolicyRevision != revision {
		return nil, nil, "", t.fail(ErrInvalid)
	}
	target := LifecycleTarget{Entity: entity, ID: NewID(), Name: draft.Name, Enabled: true}
	previous := ""
	if action == "create" {
		if draft.TargetID != "" || !validName(draft.Name) {
			return nil, nil, "", t.fail(ErrInvalid)
		}
		if entity == "device" {
			if !validID(draft.UserID) || (draft.Platform != "linux" && draft.Platform != "windows" && draft.Platform != "android") || !interval(t.now, draft.NotAfter) {
				return nil, nil, "", t.fail(ErrInvalid)
			}
			if t.tx.QueryRowContext(t.ctx, "SELECT name FROM users WHERE id=? AND enabled=1", draft.UserID).Scan(&target.UserName) != nil {
				return nil, nil, "", t.fail(ErrDenied)
			}
			target.UserID, target.Platform, target.NotAfter = draft.UserID, draft.Platform, draft.NotAfter.UTC()
		} else if draft.UserID != "" || draft.Platform != "" || !draft.NotAfter.IsZero() {
			return nil, nil, "", t.fail(ErrInvalid)
		}
		if entity == "connector" {
			target.Version = "unreported"
		}
	} else {
		if draft.UserID != "" || draft.Platform != "" || !draft.NotAfter.IsZero() || (action == "disable" && draft.Name != "") || (action == "rename" && !validName(draft.Name)) {
			return nil, nil, "", t.fail(ErrInvalid)
		}
		target, err = p.lifecycleTarget(t, admin, draft.Kind, draft.TargetID)
		if err != nil {
			return nil, nil, "", err
		}
		if action == "rename" {
			if target.Name == draft.Name {
				return nil, nil, "", t.fail(ErrInvalid)
			}
			previous, target.Name = target.Name, draft.Name
		}
	}
	change := &lifecycleChange{Kind: draft.Kind, Target: target, PreviousName: previous}
	return change, &target, previous, nil
}

func (p *PolicyEngine) applyLifecycle(t *Tx, admin adminPeer, change lifecycleChange) error {
	action, entity, ok := lifecycleKind(change.Kind)
	target := change.Target
	if !ok || entity != target.Entity || !target.Enabled || !validID(target.ID) || !validName(target.Name) {
		return t.fail(ErrDenied)
	}
	if action == "create" {
		switch entity {
		case "user":
			return t.AddUser(User{ID: target.ID, Name: target.Name, Enabled: true})
		case "device":
			var enabled bool
			if t.tx.QueryRowContext(t.ctx, "SELECT enabled FROM users WHERE id=?", target.UserID).Scan(&enabled) != nil || !enabled {
				return t.fail(ErrDenied)
			}
			return t.AddDevice(Device{ID: target.ID, UserID: target.UserID, Name: target.Name, Platform: target.Platform, Enabled: true, NotAfter: target.NotAfter})
		case "connector":
			return t.AddConnector(Connector{ID: target.ID, Name: target.Name, Version: "unreported", Enabled: true})
		}
	}
	current, err := p.lifecycleTarget(t, admin, change.Kind, target.ID)
	if err != nil {
		return err
	}
	if action == "disable" {
		if current != target || change.PreviousName != "" {
			return t.fail(ErrDenied)
		}
		return t.Disable(entity, target.ID)
	}
	current.Name = target.Name
	if current != target || !validName(change.PreviousName) {
		return t.fail(ErrDenied)
	}
	return t.renamePrincipal(entity, target.ID, change.PreviousName, target.Name)
}

func (t *Tx) renamePrincipal(entity, id, expectedName, name string) error {
	if !validID(id) || !validName(expectedName) || !validName(name) {
		return t.fail(ErrInvalid)
	}
	table := map[string]string{"user": "users", "device": "devices", "connector": "connectors"}[entity]
	if table == "" {
		return t.fail(ErrInvalid)
	}
	result, err := t.tx.ExecContext(t.ctx, "UPDATE "+table+" SET name=? WHERE id=? AND name=? AND enabled=1", name, id, expectedName)
	if err != nil {
		return t.fail(classify(err))
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return t.fail(ErrConflict)
	}
	return t.event(entity+".rename", id)
}
