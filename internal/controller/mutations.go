package controller

import (
	"database/sql"
	"strings"
	"time"
)

func (t *Tx) AddUser(v User) error {
	if e := t.guard(validID(v.ID) && validName(v.Name)); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO users VALUES(?,?,?,?)", v.ID, v.Name, v.Enabled, t.now.UnixNano()); e != nil {
		return e
	}
	return t.event("user.create", v.ID)
}
func (t *Tx) AddDevice(v Device) error {
	if e := t.guard(validID(v.ID) && validID(v.UserID) && validName(v.Name) && (v.Platform == "windows" || v.Platform == "linux" || v.Platform == "android") && interval(t.now, v.NotAfter)); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO devices VALUES(?,?,?,?,?,?)", v.ID, v.UserID, v.Name, v.Platform, v.Enabled, v.NotAfter.UnixNano()); e != nil {
		return e
	}
	return t.event("device.create", v.ID)
}
func (t *Tx) AddConnector(v Connector) error {
	if e := t.guard(validID(v.ID) && validName(v.Name) && validName(v.Version)); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO connectors VALUES(?,?,?,?)", v.ID, v.Name, v.Version, v.Enabled); e != nil {
		return e
	}
	return t.event("connector.create", v.ID)
}
func (t *Tx) AddIssuer(v Issuer) error {
	if e := t.guard(validID(v.ID) && interval(t.now, v.NotAfter)); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO issuers VALUES(?,?,?)", v.ID, v.Enabled, v.NotAfter.UnixNano()); e != nil {
		return e
	}
	return t.event("issuer.register", v.ID)
}

// RegisterCertificate stores metadata only; it neither issues nor verifies a certificate.
func (t *Tx) RegisterCertificate(v Certificate) error {
	serialOK := len(v.Serial) > 0 && len(v.Serial) <= 40 && strings.Trim(v.Serial, "0123456789abcdef") == "" && v.Serial[0] != '0'
	if e := t.guard(validID(v.ID) && validID(v.IssuerID) && validID(v.PrincipalID) && serialOK && digest(v.LeafSHA256) && digest(v.SPKISHA256) && interval(v.NotBefore, v.NotAfter) && (v.Profile == "device" || v.Profile == "connector")); e != nil {
		return e
	}
	var device, connector any
	if v.Profile == "device" {
		device = v.PrincipalID
	} else {
		connector = v.PrincipalID
	}
	var issuerEnd int64
	if e := t.tx.QueryRowContext(t.ctx, "SELECT not_after FROM issuers WHERE id=?", v.IssuerID).Scan(&issuerEnd); e != nil {
		return t.fail(ErrDenied)
	}
	if v.NotAfter.UnixNano() > issuerEnd {
		return t.fail(ErrInvalid)
	}
	if e := t.exec("INSERT INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.IssuerID, v.Serial, device, connector, v.Profile, v.LeafSHA256, v.SPKISHA256, v.NotBefore.UnixNano(), v.NotAfter.UnixNano(), v.Revoked); e != nil {
		return e
	}
	return t.event("certificate.register", v.ID)
}
func validResource(v Resource) (string, error) {
	if !validID(v.ID) || !validID(v.ConnectorID) || !validName(v.Name) || v.Revision < 1 || (v.Kind != "application" && v.Kind != "management") || v.Port < 1 || v.Port > 65535 || v.Protocol != "tcp" {
		return "", ErrInvalid
	}
	return literal(v.Address)
}
func (t *Tx) insertResource(v Resource, address string) error {
	return t.exec("INSERT INTO resources VALUES(?,?,?,?,?,?,?,?,?)", v.ID, v.Revision, v.Name, v.ConnectorID, v.Kind, address, v.Port, v.Protocol, v.Enabled)
}
func (t *Tx) AddResource(v Resource) error {
	a, e := validResource(v)
	if e != nil {
		return t.fail(e)
	}
	if e = t.guard(v.Revision == 1); e != nil {
		return e
	}
	if e = t.insertResource(v, a); e != nil {
		return e
	}
	if e = t.exec("INSERT INTO resource_heads VALUES(?,?)", v.ID, v.Revision); e != nil {
		return e
	}
	return t.event("resource.create", v.ID)
}
func (t *Tx) ReviseResource(expected int64, v Resource) error {
	a, e := validResource(v)
	if e != nil {
		return t.fail(e)
	}
	if e = t.guard(expected > 0 && v.Revision == expected+1); e != nil {
		return e
	}
	if e = t.current(v.ID, expected); e != nil {
		return e
	}
	if e = t.insertResource(v, a); e != nil {
		return e
	}
	if e = t.exec("UPDATE resource_heads SET revision=? WHERE id=?", v.Revision, v.ID); e != nil {
		return e
	}
	if e = t.exec("UPDATE grants SET enabled=0 WHERE resource_id=?", v.ID); e != nil {
		return e
	}
	if e = t.exec("UPDATE host_bindings SET enabled=0 WHERE resource_id=?", v.ID); e != nil {
		return e
	}
	if e = t.exec("UPDATE sessions SET state='closed' WHERE resource_id=? AND state='requested'", v.ID); e != nil {
		return e
	}
	return t.event("resource.revise", v.ID)
}
func (t *Tx) RenameResource(id string, expected int64, name string) error {
	if e := t.guard(validID(id) && validName(name)); e != nil {
		return e
	}
	if e := t.current(id, expected); e != nil {
		return e
	}
	if e := t.exec("UPDATE resources SET name=? WHERE id=? AND revision=?", name, id, expected); e != nil {
		return e
	}
	return t.event("resource.rename", id)
}
func (t *Tx) AddGrant(v Grant) error {
	if e := t.guard(validID(v.ID) && validID(v.UserID) && validID(v.DeviceID) && validID(v.ResourceID) && validID(v.ApprovalID) && interval(v.From, v.Until)); e != nil {
		return e
	}
	if e := t.current(v.ResourceID, v.Revision); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?)", v.ID, v.UserID, v.DeviceID, v.ResourceID, v.Revision, v.ApprovalID, v.Enabled, v.From.UnixNano(), v.Until.UnixNano()); e != nil {
		return e
	}
	return t.event("grant.create", v.ID)
}
func (t *Tx) AddHostBinding(v HostBinding) error {
	if e := t.guard(validID(v.ID) && validID(v.ConnectorID) && validID(v.ResourceID) && interval(v.From, v.Until)); e != nil {
		return e
	}
	if e := t.current(v.ResourceID, v.Revision); e != nil {
		return e
	}
	if e := t.exec("INSERT INTO host_bindings VALUES(?,?,?,?,?,?,?)", v.ID, v.ConnectorID, v.ResourceID, v.Revision, v.Enabled, v.From.UnixNano(), v.Until.UnixNano()); e != nil {
		return e
	}
	return t.event("host_binding.create", v.ID)
}

// Disable retains tombstones and atomically cancels every dependent session.
// Original certificate/grant/binding IDs identify dependencies, including old
// resource revisions. Unrelated sessions do not lose their authority.
func (t *Tx) Disable(kind, id string) error {
	if e := t.guard(validID(id)); e != nil {
		return e
	}
	tables := map[string]string{"user": "users", "device": "devices", "connector": "connectors", "issuer": "issuers", "resource": "resources", "grant": "grants", "host_binding": "host_bindings", "certificate": "certificates"}
	table, ok := tables[kind]
	if !ok {
		return t.fail(ErrInvalid)
	}
	column := "enabled=0"
	if kind == "certificate" {
		column = "revoked=1"
	}
	r, e := t.tx.ExecContext(t.ctx, "UPDATE "+table+" SET "+column+" WHERE id=?", id)
	if e != nil {
		return t.fail(classify(e))
	}
	n, e := r.RowsAffected()
	if e != nil {
		return t.fail(ErrStorage)
	}
	if n == 0 {
		return t.fail(ErrInvalid)
	}
	dependencies := map[string]string{
		"user":         "device_id IN (SELECT id FROM devices WHERE user_id=?)",
		"device":       "device_id=?",
		"connector":    "connector_certificate_id IN (SELECT id FROM certificates WHERE connector_id=?)",
		"issuer":       "(certificate_id IN (SELECT id FROM certificates WHERE issuer_id=?) OR connector_certificate_id IN (SELECT id FROM certificates WHERE issuer_id=?))",
		"resource":     "resource_id=?",
		"grant":        "grant_id=?",
		"host_binding": "host_binding_id=?",
		"certificate":  "(certificate_id=? OR connector_certificate_id=?)",
	}
	args := []any{id}
	if kind == "issuer" || kind == "certificate" {
		args = append(args, id)
	}
	if e = t.exec("UPDATE sessions SET state='closed' WHERE state='requested' AND "+dependencies[kind], args...); e != nil {
		return e
	}
	return t.event(kind+".disable", id)
}

// RecordSession creates a requested ledger record only. Phase 2 deliberately has
// no authorized/active state, token, network operation or method that grants access.
func (t *Tx) RecordSession(v Session) error {
	if e := t.guard(validID(v.ID) && validID(v.DeviceID) && validID(v.CertificateID) && validID(v.ConnectorCertificateID) && validID(v.ResourceID) && validID(v.GrantID) && validID(v.HostBindingID) && interval(t.now, v.Until) && v.Until.Sub(t.now) <= time.Hour); e != nil {
		return e
	}
	if e := t.current(v.ResourceID, v.Revision); e != nil {
		return e
	}
	var bound int64
	query := `SELECT min(d.not_after,c.not_after,sc.not_after,i.not_after,si.not_after,g.valid_until,h.valid_until)
 FROM devices d JOIN users u ON u.id=d.user_id
 JOIN certificates c ON c.device_id=d.id AND c.profile='device'
 JOIN issuers i ON i.id=c.issuer_id
 JOIN grants g ON g.device_id=d.id AND g.user_id=u.id
 JOIN resources r ON r.id=g.resource_id AND r.revision=g.revision
 JOIN connectors k ON k.id=r.connector_id
 JOIN certificates sc ON sc.connector_id=k.id AND sc.profile='connector'
 JOIN issuers si ON si.id=sc.issuer_id
 JOIN host_bindings h ON h.resource_id=r.id AND h.revision=r.revision AND h.connector_id=k.id
 WHERE d.id=? AND c.id=? AND sc.id=? AND r.id=? AND r.revision=? AND g.id=? AND h.id=?
 AND u.enabled=1 AND d.enabled=1 AND k.enabled=1 AND i.enabled=1 AND si.enabled=1
 AND c.revoked=0 AND sc.revoked=0 AND r.enabled=1 AND r.kind='application' AND g.enabled=1 AND h.enabled=1
 AND c.not_before<=? AND sc.not_before<=? AND g.valid_from<=? AND h.valid_from<=?`
	n := t.now.UnixNano()
	e := t.tx.QueryRowContext(t.ctx, query, v.DeviceID, v.CertificateID, v.ConnectorCertificateID, v.ResourceID, v.Revision, v.GrantID, v.HostBindingID, n, n, n, n).Scan(&bound)
	if e != nil {
		if errorsIsNoRows(e) {
			return t.fail(ErrDenied)
		}
		return t.fail(ErrStorage)
	}
	if n >= bound || v.Until.UnixNano() > bound {
		return t.fail(ErrDenied)
	}
	if e = t.exec("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.DeviceID, v.CertificateID, v.ConnectorCertificateID, v.ResourceID, v.Revision, v.GrantID, v.HostBindingID, "requested", n, v.Until.UnixNano()); e != nil {
		return e
	}
	return t.event("session.record", v.ID)
}
func errorsIsNoRows(e error) bool { return e == sql.ErrNoRows }
func (t *Tx) EndSession(id, state string) error {
	if e := t.guard(validID(id) && (state == "closed" || state == "denied" || state == "expired")); e != nil {
		return e
	}
	r, e := t.tx.ExecContext(t.ctx, "UPDATE sessions SET state=? WHERE id=? AND state='requested'", state, id)
	if e != nil {
		return t.fail(classify(e))
	}
	n, e := r.RowsAffected()
	if e != nil {
		return t.fail(ErrStorage)
	}
	if n != 1 {
		return t.fail(ErrConflict)
	}
	return t.event("session."+state, id)
}
