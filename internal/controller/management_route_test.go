package controller

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

type managementFixture struct {
	a     *adminFixture
	p     *policyFixture
	route *ManagementRoute
	grant Grant
	host  HostBinding
}

func newManagementFixture(t *testing.T) *managementFixture {
	t.Helper()
	a := adminSeed(t)
	p := policyFixtureFor(t, a.f)
	f := a.f.f
	resource := f.resource
	resource.Kind, resource.Revision = "management", 2
	grant, host := f.grant, f.host
	grant.ID, grant.Revision, host.ID, host.Revision = NewID(), 2, NewID(), 2
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if err := tx.ReviseResource(1, resource); err != nil {
			return err
		}
		if err := tx.AddGrant(grant); err != nil {
			return err
		}
		return tx.AddHostBinding(host)
	}))
	route, err := NewManagementRoute(f.s, ManagementRouteConfig{Administrators: a.trust, Connectors: p.connector.trust, ConnectorLeafDER: p.connectorLeaf, ResourceID: resource.ID, ConnectorID: resource.ConnectorID, Revision: 2, Address: resource.Address, Port: resource.Port})
	must(t, err)
	return &managementFixture{a, p, route, grant, host}
}

func TestManagementRouteRequiresExactAdministratorAndDedicatedResource(t *testing.T) {
	f := newManagementFixture(t)
	s := f.a.f.f.s
	before := summary(t, s)
	access, err := f.route.Check(ctx, f.a.conn)
	must(t, err)
	if access.Version != 1 || access.DeviceID != f.a.deviceID || access.UserID != f.a.userID || access.CertificateFingerprint != pki.Hash(f.a.identity.Certificate[0]) || access.Resource.ID != f.grant.ResourceID || access.Resource.Revision != 2 || access.Resource.ConnectorID != f.route.config.ConnectorID || access.Resource.Address != f.route.config.Address || access.Resource.Port != f.route.config.Port || access.GrantID != f.grant.ID || access.BindingID != f.host.ID || access.PolicyRevision < 1 || access.CheckedAt.IsZero() || !digest(access.RouteFingerprint) || before != summary(t, s) {
		t.Fatal("management observation omitted exact scope or created authority")
	}
	for name, conn := range map[string]*tls.Conn{"nil": nil, "ordinary_same_device": f.p.deviceConn, "connector": f.p.connectorConn} {
		t.Run(name, func(t *testing.T) {
			if result, err := f.route.Check(ctx, conn); err == nil || result.Version != 0 {
				t.Fatal("non-administrator obtained management scope")
			}
		})
	}
	for name, leaf := range map[string][]byte{"ordinary_device": f.p.deviceLeaf, "administrator": f.a.identity.Certificate[0]} {
		t.Run("ordinary_engine_"+name, func(t *testing.T) {
			if _, err := f.p.engine.Authorize(ctx, f.p.connectorConn, AuthorizeRequest{Version: 1, ClientLeafDER: leaf, ResourceID: f.grant.ResourceID, Revision: 2}); err == nil {
				t.Fatal("ordinary policy acquired management authority")
			}
		})
	}
	catalog, err := f.p.engine.Catalog(ctx, f.p.deviceConn)
	must(t, err)
	if len(catalog) != 0 {
		t.Fatal("ordinary catalog exposed management resource")
	}
	must(t, verifyAudit(ctx, s.db))
}

func TestManagementRouteLiveDenials(t *testing.T) {
	for _, name := range []string{"user", "device", "administrator", "connector", "connector_certificate", "connector_issuer", "pending_connector", "resource", "grant", "host_binding", "expired_grant", "future_grant", "ambiguous_grant", "ambiguous_host", "wrong_revision", "changed_port", "changed_address", "application_kind", "shared_connector", "emergency", "clock_rollback"} {
		t.Run(name, func(t *testing.T) {
			f := newManagementFixture(t)
			s, actor := f.a.f.f.s, f.a.f.f.actor
			_, err := f.route.Check(ctx, f.a.conn)
			must(t, err)
			var certificate string
			must(t, s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(f.p.connectorLeaf)).Scan(&certificate))
			ids := map[string]string{"user": f.a.userID, "device": f.a.deviceID, "connector": f.route.config.ConnectorID, "resource": f.grant.ResourceID, "grant": f.grant.ID, "host_binding": f.host.ID}
			if id, ok := ids[name]; ok {
				must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable(name, id) }))
			} else {
				switch name {
				case "administrator":
					_, err = s.db.Exec("UPDATE admin_devices SET enabled=0")
				case "connector_certificate":
					err = s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("certificate", certificate) })
				case "connector_issuer":
					err = s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("issuer", f.p.connector.trust.IssuerID()) })
				case "pending_connector":
					_, err = s.db.Exec("UPDATE enrollments SET state='issued' WHERE certificate_id=?", certificate)
				case "expired_grant":
					s.now = func() time.Time { return f.grant.Until }
				case "future_grant":
					_, err = s.db.Exec("UPDATE grants SET valid_from=? WHERE id=?", s.now().Add(time.Minute).UnixNano(), f.grant.ID)
				case "ambiguous_grant":
					grant := f.grant
					grant.ID = NewID()
					err = s.Update(ctx, actor, func(tx *Tx) error { return tx.AddGrant(grant) })
				case "ambiguous_host":
					host := f.host
					host.ID = NewID()
					err = s.Update(ctx, actor, func(tx *Tx) error { return tx.AddHostBinding(host) })
				case "wrong_revision":
					f.route.config.Revision++
				case "changed_port":
					_, err = s.db.Exec("UPDATE resources SET port=443 WHERE id=? AND revision=2", f.grant.ResourceID)
				case "changed_address":
					_, err = s.db.Exec("UPDATE resources SET address='192.168.50.20' WHERE id=? AND revision=2", f.grant.ResourceID)
				case "application_kind":
					_, err = s.db.Exec("UPDATE resources SET kind='application' WHERE id=? AND revision=2", f.grant.ResourceID)
				case "shared_connector":
					resource := f.a.f.f.resource
					resource.ID = NewID()
					err = s.Update(ctx, actor, func(tx *Tx) error { return tx.AddResource(resource) })
				case "emergency":
					s.emergency.Store(true)
				case "clock_rollback":
					s.now = func() time.Time { return time.Unix(1, 0) }
				}
				must(t, err)
			}
			before := summary(t, s)
			if result, err := f.route.Check(ctx, f.a.conn); err == nil || result.Version != 0 {
				t.Fatal("changed authority retained management access")
			}
			if summary(t, s) != before {
				t.Fatal("denied route changed authority")
			}
		})
	}
}

func TestManagementGrantRecheckedInsideRequestTransaction(t *testing.T) {
	f := newManagementFixture(t)
	s, actor := f.a.f.f.s, f.a.f.f.actor
	request, err := f.route.requestContext(ctx, f.a.conn)
	must(t, err)
	must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
	called := false
	err = s.Update(request, actor, func(tx *Tx) error { called = true; return tx.AddUser(User{NewID(), "must not commit", true}) })
	if err == nil || called {
		t.Fatal("revocation raced request transaction")
	}
	other := seed(t)
	if err := other.s.Update(request, other.actor, func(*Tx) error { called = true; return nil }); err == nil || called {
		t.Fatal("bound request crossed controller stores")
	}
}

func TestManagementHTTPSRevokesExistingAndFreshTLS(t *testing.T) {
	f := newManagementFixture(t)
	c := PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: f.a.trust, AdministratorVerifier: f.a.verifier}
	h := servePolicyRoute(t, f.p.engine, c, f.a.identity, f.route)
	get := func(reuse bool) int {
		t.Helper()
		r, err := http.NewRequest(http.MethodGet, "https://"+h.host+"/admin", nil)
		must(t, err)
		r.Header.Set("X-Admin", "true")
		r.Header.Set("X-Forwarded-User", f.a.userID)
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if reuse && !info.Reused {
				t.Error("existing TLS connection was not reused")
			}
		}}
		response, err := h.client.Do(r.WithContext(httptrace.WithClientTrace(context.Background(), trace)))
		if err != nil {
			return 0
		}
		_, err = io.Copy(io.Discard, response.Body)
		must(t, err)
		must(t, response.Body.Close())
		return response.StatusCode
	}
	if get(false) != http.StatusOK {
		t.Fatal("permitted management HTTPS failed")
	}
	s, actor := f.a.f.f.s, f.a.f.f.actor
	must(t, s.Update(ctx, actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
	if get(true) != http.StatusForbidden {
		t.Fatal("revoked route survived on existing TLS")
	}
	h.client.CloseIdleConnections()
	if get(false) != 0 {
		t.Fatal("fresh TLS accepted revoked management grant")
	}
}

func TestManagementRouteConfigurationCannotWidenAuthority(t *testing.T) {
	f := newManagementFixture(t)
	for _, name := range []string{"no_store", "ordinary_profile", "missing_admin", "missing_connector", "wrong_connector_profile", "different_deployment", "bad_resource", "bad_connector", "wrong_connector_leaf", "revision", "port", "loopback", "hostname", "missing_leaf"} {
		t.Run(name, func(t *testing.T) {
			c, s := f.route.config, f.route.store
			switch name {
			case "no_store":
				s = nil
			case "ordinary_profile":
				c.Administrators = f.p.device.trust
			case "missing_admin":
				c.Administrators = nil
			case "missing_connector":
				c.Connectors = nil
			case "wrong_connector_profile":
				c.Connectors = f.a.trust
			case "different_deployment":
				c.Administrators = adminSeed(t).trust
			case "bad_resource":
				c.ResourceID = "management"
			case "bad_connector":
				c.ConnectorID = "management"
			case "wrong_connector_leaf":
				c.ConnectorID = NewID()
			case "revision":
				c.Revision = 0
			case "port":
				c.Port = 0
			case "loopback":
				c.Address = "127.0.0.1"
			case "hostname":
				c.Address = "admin.portico.test"
			case "missing_leaf":
				c.ConnectorLeafDER = nil
			}
			if _, err := NewManagementRoute(s, c); err == nil {
				t.Fatal("invalid management scope was accepted")
			}
		})
	}
	for _, profile := range []pki.Profile{pki.Device, pki.Connector} {
		if _, err := f.p.engine.NewManagementHTTPServer(PolicyHTTPConfig{Profile: profile, AdministratorTrust: f.a.trust}, f.route); err == nil {
			t.Fatal("ordinary HTTP role selected management handler")
		}
	}
	c := f.route.config
	c.ConnectorLeafDER = append([]byte(nil), c.ConnectorLeafDER...)
	route, err := NewManagementRoute(f.route.store, c)
	must(t, err)
	c.ConnectorLeafDER[0] ^= 0xff
	if _, err := route.Check(ctx, f.a.conn); err != nil {
		t.Fatal("caller changed retained route certificate")
	}
}

func TestManagementHTTPSPreservesHardwareApprovedMutation(t *testing.T) {
	f := newManagementFixture(t)
	f.a.setupFactors(t)
	h := servePolicyRoute(t, f.p.engine, PolicyHTTPConfig{Profile: pki.Administrator, Host: "admin.portico.test", AdministratorTrust: f.a.trust, AdministratorVerifier: f.a.verifier}, f.a.identity, f.route)
	access, err := f.route.Check(ctx, f.a.conn)
	must(t, err)
	var preview PolicyPreview
	h.post(t, "/api/v1/admin/policy/preview", PolicyDraft{Lifecycle: &LifecycleDraft{Kind: "create-user", PolicyRevision: access.PolicyRevision, Name: "Managed administrator operation"}}, &preview)
	var challenge AdminChallenge
	h.post(t, "/api/v1/admin/policy/challenge", previewApprovalRequest{preview.ID, preview.Digest}, &challenge)
	response := f.a.assertion(t, f.a.keys[1], challenge)
	h.post(t, "/api/v1/admin/policy/confirm", finishApprovalRequest{challenge.ID, response}, nil)
	var count int
	must(t, f.a.f.f.s.db.QueryRow("SELECT count(*) FROM users WHERE name=? AND enabled=1", "Managed administrator operation").Scan(&count))
	if count != 1 {
		t.Fatal("managed HTTPS did not commit exactly the hardware-approved operation")
	}
	must(t, verifyAudit(ctx, f.a.f.f.s.db))
}
