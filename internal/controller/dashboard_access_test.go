package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

type accessFixture struct {
	a       *adminFixture
	v       *policyFixture
	user    User
	device  Device
	grant   Grant
	leaf    []byte
	request AccessInspectionRequest
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	a := adminSeed(t)
	v := policyFixtureFor(t, a.f)
	f := a.f.f
	user := User{NewID(), "Application user", true}
	device := Device{NewID(), user.ID, "Linux workstation", "linux", true, f.device.NotAfter}
	grant := f.grant
	grant.ID, grant.UserID, grant.DeviceID = NewID(), user.ID, device.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if err := tx.AddUser(user); err != nil {
			return err
		}
		if err := tx.AddDevice(device); err != nil {
			return err
		}
		return tx.AddGrant(grant)
	}))
	_, leaf, _ := enrolledPolicyPeer(t, a.f, device.ID)
	request := AccessInspectionRequest{ResourceID: f.resource.ID, Revision: 1}
	must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(leaf)).Scan(&request.DeviceCertificateID))
	must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(v.connectorLeaf)).Scan(&request.ConnectorCertificateID))
	return &accessFixture{a, v, user, device, grant, leaf, request}
}

func TestDashboardAccessMatchesRealAuthorizationWithoutSideEffects(t *testing.T) {
	f := newAccessFixture(t)
	s := f.a.f.f.s
	before := summary(t, s)
	view, err := f.v.engine.InspectAccess(ctx, f.a.conn, f.a.trust, f.request)
	must(t, err)
	if !view.Allowed || view.Reason != "allowed_by_current_policy" || view.Version != 1 || view.PolicyRevision == 0 || view.ObservedAt.IsZero() || view.UserID != f.user.ID || view.DeviceID != f.device.ID || view.DeviceName != f.device.Name || view.Resource == nil || view.GrantID != f.grant.ID {
		t.Fatal("inspection omitted exact effective identity/policy")
	}
	if before != summary(t, s) {
		t.Fatal("inspection changed authoritative state")
	}
	permit, err := f.v.engine.Authorize(ctx, f.v.connectorConn, AuthorizeRequest{Version: 1, ClientLeafDER: f.leaf, ResourceID: f.request.ResourceID, Revision: f.request.Revision})
	must(t, err)
	if !reflect.DeepEqual(*view.Resource, permit.Resource) || view.DeviceID != permit.DeviceID || view.ConnectorID != permit.ConnectorID || view.PolicyRevision != permit.PolicyRevision {
		t.Fatal("inspection diverged from actual authorization")
	}
	encoded, err := json.Marshal(view)
	must(t, err)
	for _, forbidden := range []string{permit.SessionID, "SessionID", "LeaseUntil", "ActivateUntil", "ClientLeafDER", "CertificateDER", "PrivateKey", "InvitationSecret"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("inspection returned authority or credential material")
		}
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestDashboardAccessDenialsAgreeWithAuthorization(t *testing.T) {
	for _, kind := range []string{"disabled_user", "disabled_device", "revoked_device_certificate", "disabled_device_issuer", "pending_identity", "disabled_connector", "revoked_connector_certificate", "disabled_resource", "disabled_grant", "disabled_hosting", "ambiguous_grant", "ambiguous_hosting", "expired_grant", "wrong_revision", "unknown_resource", "protected_destination", "quota"} {
		t.Run(kind, func(t *testing.T) {
			f := newAccessFixture(t)
			s, actor := f.a.f.f.s, f.a.f.f.actor
			request := f.request
			var hostingID string
			must(t, s.db.QueryRow("SELECT id FROM host_bindings WHERE resource_id=?", request.ResourceID).Scan(&hostingID))
			p := f.v.engine
			switch kind {
			case "disabled_user":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("user", f.user.ID) }))
			case "disabled_device":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("device", f.device.ID) }))
			case "revoked_device_certificate":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("certificate", request.DeviceCertificateID) }))
			case "disabled_device_issuer":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("issuer", p.config.DeviceTrust.IssuerID()) }))
			case "pending_identity":
				_, err := s.db.Exec("UPDATE enrollments SET state='issued' WHERE certificate_id=?", request.DeviceCertificateID)
				must(t, err)
			case "disabled_connector":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("connector", f.a.f.f.connector.ID) }))
			case "revoked_connector_certificate":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("certificate", request.ConnectorCertificateID) }))
			case "disabled_resource":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("resource", request.ResourceID) }))
			case "disabled_grant":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
			case "disabled_hosting":
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("host_binding", hostingID) }))
			case "ambiguous_grant":
				grant := f.grant
				grant.ID = NewID()
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.AddGrant(grant) }))
			case "ambiguous_hosting":
				must(t, s.Update(ctx, actor, func(tx *Tx) error {
					return tx.AddHostBinding(HostBinding{NewID(), f.a.f.f.connector.ID, request.ResourceID, 1, true, f.grant.From, f.grant.Until})
				}))
			case "expired_grant":
				s.now = func() time.Time { return f.grant.Until }
			case "wrong_revision":
				request.Revision++
			case "unknown_resource":
				request.ResourceID = NewID()
			case "protected_destination":
				config := p.config
				config.ProtectedNetworks = append(config.ProtectedNetworks, netip.MustParsePrefix("192.168.50.0/24"))
				var err error
				p, err = NewPolicyEngine(s, config)
				must(t, err)
			case "quota":
				for range p.config.MaxDeviceSessions {
					_, err := p.Authorize(ctx, f.v.connectorConn, AuthorizeRequest{Version: 1, ClientLeafDER: f.leaf, ResourceID: request.ResourceID, Revision: request.Revision})
					must(t, err)
				}
			}
			before := summary(t, s)
			view, err := p.InspectAccess(ctx, f.a.conn, f.a.trust, request)
			must(t, err)
			if view.Allowed || view.Reason == "" || view.Resource != nil || view.GrantID != "" || view.HostBindingID != "" || before != summary(t, s) {
				t.Fatal("denied inspection disclosed permission or changed state")
			}
			if _, err := p.Authorize(ctx, f.v.connectorConn, AuthorizeRequest{Version: 1, ClientLeafDER: f.leaf, ResourceID: request.ResourceID, Revision: request.Revision}); err == nil {
				t.Fatal("actual authorization disagrees with inspection denial")
			}
			if before != summary(t, s) {
				t.Fatal("denied real authorization changed state")
			}
		})
	}
}

func TestDashboardAccessAuthenticationStalenessAndStorageFailure(t *testing.T) {
	f := newAccessFixture(t)
	s, p := f.a.f.f.s, f.v.engine
	view, err := p.InspectAccess(ctx, f.a.conn, f.a.trust, f.request)
	must(t, err)
	request := f.request
	request.PolicyRevision = view.PolicyRevision
	must(t, s.Update(ctx, f.a.f.f.actor, func(tx *Tx) error { return tx.AddUser(User{NewID(), "Another user", true}) }))
	if got, err := p.InspectAccess(ctx, f.a.conn, f.a.trust, request); err == nil || !reflect.DeepEqual(got, AccessInspection{}) {
		t.Fatal("stale inspection returned data")
	}
	if got, err := p.InspectAccess(ctx, nil, f.a.trust, f.request); err == nil || got.Allowed {
		t.Fatal("inspection accepted missing TLS identity")
	}
	if got, err := p.InspectAccess(ctx, f.v.deviceConn, f.a.trust, f.request); err == nil || got.Allowed {
		t.Fatal("ordinary TLS peer entered inspection")
	}
	_, err = s.db.Exec("ALTER TABLE grants RENAME TO inaccessible_fixture_grants")
	must(t, err)
	if got, err := p.InspectAccess(ctx, f.a.conn, f.a.trust, f.request); err != ErrStorage || !reflect.DeepEqual(got, AccessInspection{}) {
		t.Fatal("storage failure was misreported as a verified policy result")
	}
	_, err = s.db.Exec("ALTER TABLE inaccessible_fixture_grants RENAME TO grants")
	must(t, err)
	s.EmergencyDeny()
	if got, err := p.InspectAccess(ctx, f.a.conn, f.a.trust, f.request); err == nil || !reflect.DeepEqual(got, AccessInspection{}) {
		t.Fatal("emergency denial returned inspection data")
	}
}

func TestDashboardAccessHTTPAndLiveAdministratorRevocation(t *testing.T) {
	f := newAccessFixture(t)
	server := servePolicy(t, f.v.engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: f.a.trust, AdministratorVerifier: f.a.verifier}, f.a.identity)
	var view AccessInspection
	server.post(t, "/api/v1/admin/dashboard/access", f.request, &view)
	if !view.Allowed {
		t.Fatal("real TLS inspection unavailable")
	}
	valid, err := json.Marshal(f.request)
	must(t, err)
	request := func(body, origin string) (int, []byte, bool) {
		r, err := http.NewRequest(http.MethodPost, "https://"+server.host+"/api/v1/admin/dashboard/access", strings.NewReader(body))
		must(t, err)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Admin", "true")
		reused := false
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		response, err := server.client.Do(r)
		must(t, err)
		data, err := io.ReadAll(response.Body)
		must(t, err)
		must(t, response.Body.Close())
		return response.StatusCode, data, reused
	}
	for _, body := range []string{"null", "{}", string(valid) + "{}", strings.TrimSuffix(string(valid), "}") + `,"ClientLeafDER":"forged"}`, strings.TrimSuffix(string(valid), "}") + `,"revision":1}`} {
		status, data, _ := request(body, "https://"+server.host)
		if status != http.StatusForbidden || string(data) != `{"error":"request rejected"}` {
			t.Fatal("hostile inspection returned data")
		}
	}
	status, _, _ := request(string(valid), "https://attacker.test")
	if status != http.StatusForbidden {
		t.Fatal("foreign origin entered inspection")
	}
	must(t, f.a.f.f.s.Update(ctx, f.a.f.f.actor, func(tx *Tx) error { return tx.Disable("device", f.a.f.f.device.ID) }))
	status, data, reused := request(string(valid), "https://"+server.host)
	if !reused || status != http.StatusForbidden || string(data) != `{"error":"request rejected"}` {
		t.Fatal("revoked administrator retained access inspection")
	}
}

func TestPolicyReadRefactorPreservesStickyAuthorizationFailure(t *testing.T) {
	f := newAccessFixture(t)
	s := f.a.f.f.s
	before := summary(t, s)
	err := s.Update(ctx, f.a.f.f.actor, func(tx *Tx) error {
		device, err := tx.peer(f.v.engine.config.DeviceTrust, f.leaf, false)
		if err != nil {
			return err
		}
		connector, err := tx.peer(f.v.engine.config.ConnectorTrust, f.v.connectorLeaf, false)
		if err != nil {
			return err
		}
		_, _ = f.v.engine.match(tx, device, connector, NewID(), 1)
		return tx.AddUser(User{NewID(), "Must not commit", true})
	})
	if err == nil || before != summary(t, s) {
		t.Fatal("ignored policy denial escaped transaction failure")
	}
}
