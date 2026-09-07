package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func (v *policyFixture) connectorCheck() ConnectorCheck {
	return ConnectorCheck{Version: PolicyProtocol, ResourceID: v.device.f.resource.ID, Revision: v.device.f.resource.Revision, ConnectorLeafDER: v.connectorLeaf}
}

func TestClientConnectorCheckRechecksAllLiveAuthority(t *testing.T) {
	for _, name := range []string{"valid", "user", "device", "connector", "host_binding", "grant", "resource", "issuer", "leaf", "revision", "version", "oversize", "wrong_profile", "wrong_client", "nil_transport", "expired_grant", "rollback", "emergency"} {
		t.Run(name, func(t *testing.T) {
			v := newPolicyFixture(t)
			f := v.device.f
			s := f.s
			r := v.connectorCheck()
			conn := v.deviceConn
			ids := map[string]string{"user": f.user.ID, "device": f.device.ID, "connector": f.connector.ID, "host_binding": f.host.ID, "grant": f.grant.ID, "resource": f.resource.ID, "issuer": v.connector.trust.IssuerID()}
			if id, ok := ids[name]; ok {
				must(t, s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable(name, id) }))
			} else {
				switch name {
				case "leaf":
					var id string
					must(t, s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(v.connectorLeaf)).Scan(&id))
					must(t, s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("certificate", id) }))
				case "revision":
					r.Revision++
				case "version":
					r.Version++
				case "oversize":
					r.ConnectorLeafDER = make([]byte, pki.MaxDER+1)
				case "wrong_profile":
					r.ConnectorLeafDER = v.deviceLeaf
				case "wrong_client":
					conn = v.connectorConn
				case "nil_transport":
					conn = nil
				case "expired_grant":
					s.now = func() time.Time { return f.grant.Until }
				case "rollback":
					now := s.now().Add(-time.Second)
					s.now = func() time.Time { return now }
				case "emergency":
					s.EmergencyDeny()
				}
			}
			before := summary(t, s)
			got, e := v.engine.CheckConnector(ctx, conn, r)
			if name == "valid" {
				must(t, e)
				if got.Resource.Address != f.resource.Address || got.Resource.Port != f.resource.Port || got.ConnectorCertificateID == "" || got.CheckedAt != s.now() || got.PolicyRevision < 1 {
					t.Fatal("check widened or omitted authority context")
				}
			} else if e == nil || !reflect.DeepEqual(got, ConnectorStatus{}) {
				t.Fatal("invalid live check returned resource authority")
			}
			if summary(t, s) != before {
				t.Fatal("status check created a session or changed authority")
			}
		})
	}
}

func TestConnectorHostingSnapshotIsIndependentAndExact(t *testing.T) {
	for _, name := range []string{"valid", "grant_disabled", "resource_disabled", "host_disabled", "future_host", "expired_host", "management", "ambiguous", "protected", "wrong_profile", "nil_transport", "too_many"} {
		t.Run(name, func(t *testing.T) {
			v := newPolicyFixture(t)
			f := v.device.f
			conn := v.connectorConn
			switch name {
			case "grant_disabled":
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
			case "resource_disabled":
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("resource", f.resource.ID) }))
			case "host_disabled":
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("host_binding", f.host.ID) }))
			case "future_host":
				_, e := f.s.db.Exec("UPDATE host_bindings SET valid_from=? WHERE id=?", f.s.now().Add(time.Minute).UnixNano(), f.host.ID)
				must(t, e)
			case "expired_host":
				f.s.now = func() time.Time { return f.host.Until }
			case "management":
				_, e := f.s.db.Exec("UPDATE resources SET kind='management' WHERE id=?", f.resource.ID)
				must(t, e)
			case "ambiguous":
				h := f.host
				h.ID = NewID()
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddHostBinding(h) }))
			case "protected":
				_, e := f.s.db.Exec("UPDATE resources SET address='10.99.0.1' WHERE id=?", f.resource.ID)
				must(t, e)
			case "wrong_profile":
				conn = v.deviceConn
			case "nil_transport":
				conn = nil
			case "too_many":
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
					for i := 0; i < MaxHostingResources; i++ {
						r := f.resource
						r.ID = NewID()
						if e := tx.AddResource(r); e != nil {
							return e
						}
						h := f.host
						h.ID = NewID()
						h.ResourceID = r.ID
						if e := tx.AddHostBinding(h); e != nil {
							return e
						}
					}
					return nil
				}))
			}
			before := summary(t, f.s)
			snapshot, e := v.engine.Hosting(ctx, conn)
			switch name {
			case "ambiguous", "protected", "wrong_profile", "nil_transport", "too_many":
				if e == nil || !reflect.DeepEqual(snapshot, HostingSnapshot{}) {
					t.Fatal("unsafe/partial hosting snapshot returned")
				}
			default:
				must(t, e)
				want := 0
				if name == "valid" || name == "grant_disabled" {
					want = 1
				}
				if len(snapshot.Resources) != want || snapshot.ConnectorID != f.connector.ID || snapshot.ConnectorCertificateID == "" || snapshot.PolicyRevision < 1 || !snapshot.Until.After(snapshot.CheckedAt) {
					t.Fatal("incomplete hosting snapshot")
				}
				if want == 1 {
					r := snapshot.Resources[0]
					if r.HostBindingID != f.host.ID || r.Resource.ID != f.resource.ID || r.Resource.Address != f.resource.Address || r.Resource.Port != f.resource.Port || r.Until != f.host.Until || snapshot.Until.Sub(snapshot.CheckedAt) != v.engine.config.LeaseLifetime {
						t.Fatal("hosting snapshot changed tuple or bounds")
					}
				}
			}
			if summary(t, f.s) != before {
				t.Fatal("hosting read changed authority")
			}
		})
	}
}

func TestCancellationDeliveryRepeatsUntilAtomicReceipt(t *testing.T) {
	v := newPolicyFixture(t)
	f := v.device.f
	var permits []Authorization
	for i := 0; i < 3; i++ {
		a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
		must(t, e)
		permits = append(permits, a)
	}
	ack := CancellationAck{Version: 1, SessionID: permits[0].SessionID}
	if e := v.engine.AcknowledgeCancellation(ctx, v.connectorConn, ack); e == nil {
		t.Fatal("active session accepted closure report")
	}
	empty, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(empty.Items) != 0 {
		t.Fatal("live sessions appeared cancelled")
	}
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
	before := summary(t, f.s)
	batch, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 1})
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].Reason != "closed" {
		t.Fatalf("missing first cancellation: %+v", batch.Items)
	}
	repeat, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 1})
	must(t, e)
	if !reflect.DeepEqual(batch, repeat) || summary(t, f.s) != before {
		t.Fatal("lost poll response skipped or mutated pending cancellation")
	}
	var count int
	must(t, f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&count))
	if count != 0 {
		t.Fatal("controller denial invented socket closure")
	}
	ack.SessionID = batch.Items[0].SessionID
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- v.engine.AcknowledgeCancellation(ctx, v.connectorConn, ack) }()
	}
	wg.Wait()
	close(results)
	for e := range results {
		must(t, e)
	}
	after := summary(t, f.s)
	if after.AuditSequence != before.AuditSequence+1 {
		t.Fatal("concurrent receipt duplicated audit or failed to persist")
	}
	remaining, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(remaining.Items) != 2 {
		t.Fatal("acknowledgment skipped unrelated cancellations")
	}
	for _, item := range remaining.Items {
		must(t, v.engine.AcknowledgeCancellation(ctx, v.connectorConn, CancellationAck{Version: 1, SessionID: item.SessionID}))
	}
	done, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(done.Items) != 0 {
		t.Fatal("reported closures remained in pending batch")
	}
	if _, e := v.engine.Renew(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: ack.SessionID, Sequence: 1}); e == nil {
		t.Fatal("receipt reactivated terminal session")
	}
	if _, e = f.s.db.Exec("UPDATE session_closure_receipts SET reported_at=reported_at+1"); e == nil {
		t.Fatal("receipt was mutable")
	}
	must(t, verifyAudit(ctx, f.s.db))
	// Receipt loss/retry after a controller restart cannot resurrect pending
	// work or append a second acknowledgment event.
	must(t, f.s.Close())
	reopened, e := Open(ctx, f.dir)
	must(t, e)
	defer reopened.Close()
	engine, e := NewPolicyEngine(reopened, v.engine.config)
	must(t, e)
	beforeRestartAck := summary(t, reopened)
	batch, e = engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(batch.Items) != 0 {
		t.Fatal("restart lost durable closure receipts")
	}
	must(t, engine.AcknowledgeCancellation(ctx, v.connectorConn, ack))
	if summary(t, reopened) != beforeRestartAck {
		t.Fatal("retried receipt after restart duplicated audit")
	}
}

func TestCancellationExpiryRollsBackWithAuditFailure(t *testing.T) {
	v := newPolicyFixture(t)
	f := v.device.f
	a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	f.s.now = func() time.Time { return a.LeaseUntil }
	_, e = f.s.db.Exec("CREATE TRIGGER reject_expiry_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture expiry failure'); END")
	must(t, e)
	before := summary(t, f.s)
	batch, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	if e == nil || batch.Version != 0 {
		t.Fatal("failed expiry returned cancellation batch")
	}
	var count int
	must(t, f.s.db.QueryRow("SELECT count(*) FROM session_cancellations").Scan(&count))
	if count != 0 || summary(t, f.s) != before {
		t.Fatal("failed expiry partially changed session/audit")
	}
	if _, e = v.engine.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: 1}); e == nil {
		t.Fatal("rollback extended expired authorization")
	}
	_, e = f.s.db.Exec("DROP TRIGGER reject_expiry_audit")
	must(t, e)
	batch, e = v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].Reason != "expired" {
		t.Fatal("expiry did not recover after storage failure")
	}
}

func TestCancellationOwnershipExpiryAndStorageFailures(t *testing.T) {
	for _, name := range []string{"wrong_profile", "replacement_leaf", "unknown_session", "version", "limit", "expired", "audit_failure", "receipt_failure", "cancelled_context"} {
		t.Run(name, func(t *testing.T) {
			v := newPolicyFixture(t)
			f := v.device.f
			a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
			must(t, e)
			if name != "expired" {
				must(t, v.engine.CloseSession(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: 1}))
			}
			conn := v.connectorConn
			ack := CancellationAck{Version: 1, SessionID: a.SessionID}
			request := CancellationRequest{Version: 1, Limit: 64}
			callCtx := ctx
			switch name {
			case "wrong_profile":
				conn = v.deviceConn
			case "replacement_leaf":
				conn, _, _ = enrolledPolicyPeer(t, v.connector, f.connector.ID)
			case "unknown_session":
				ack.SessionID = NewID()
			case "version":
				ack.Version = 2
				request.Version = 2
			case "limit":
				request.Limit = 65
			case "expired":
				f.s.now = func() time.Time { return a.LeaseUntil }
			case "audit_failure":
				_, e = f.s.db.Exec("CREATE TRIGGER reject_closure_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END")
				must(t, e)
			case "receipt_failure":
				_, e = f.s.db.Exec("CREATE TRIGGER reject_closure_receipt BEFORE INSERT ON session_closure_receipts BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END")
				must(t, e)
			case "cancelled_context":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if name == "expired" {
				batch, e := v.engine.Cancellations(callCtx, conn, request)
				must(t, e)
				if len(batch.Items) != 1 || batch.Items[0].Reason != "expired" {
					t.Fatal("expired lease lacked cancellation")
				}
				must(t, v.engine.AcknowledgeCancellation(callCtx, conn, ack))
				return
			}
			before := summary(t, f.s)
			if name == "limit" {
				if _, e = v.engine.Cancellations(callCtx, conn, request); e == nil {
					t.Fatal("unbounded cancellation batch accepted")
				}
				return
			}
			if e = v.engine.AcknowledgeCancellation(callCtx, conn, ack); e == nil {
				t.Fatal("unauthorized/failed closure report accepted")
			}
			if summary(t, f.s) != before {
				t.Fatal("failed closure report committed partial audit")
			}
			var count int
			must(t, f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&count))
			if count != 0 {
				t.Fatal("failed closure report persisted")
			}
			if name == "replacement_leaf" {
				batch, e := v.engine.Cancellations(ctx, conn, request)
				must(t, e)
				if len(batch.Items) != 0 {
					t.Fatal("new certificate inherited old cancellation authority")
				}
			}
		})
	}
}

func TestVersionFourMigrationPreservesCancellationsAndRollsBack(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrate", true: "rollback"}[reject], func(t *testing.T) {
			v := newPolicyFixture(t)
			f := v.device.f
			a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
			must(t, e)
			_, e = f.s.db.Exec("DROP TABLE session_closure_receipts; PRAGMA user_version=4")
			must(t, e)
			hash := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema + policySchema))
			old := hex.EncodeToString(hash[:])
			_, e = f.s.db.Exec("UPDATE meta SET schema_digest=?", old)
			must(t, e)
			if reject {
				_, e = f.s.db.Exec("CREATE TRIGGER reject_closure_migration BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture migration failure'); END")
				must(t, e)
			}
			must(t, f.s.Close())
			reopened, e := Open(ctx, f.dir)
			if reject {
				if e == nil {
					_ = reopened.Close()
					t.Fatal("migration ignored audit failure")
				}
				db, e := sql.Open("sqlite", databaseURI(filepath.Join(f.dir, "controller.sqlite")))
				must(t, e)
				defer db.Close()
				var version, tables int
				var digest, state string
				must(t, db.QueryRow("PRAGMA user_version").Scan(&version))
				must(t, db.QueryRow("SELECT schema_digest FROM meta").Scan(&digest))
				must(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='session_closure_receipts'").Scan(&tables))
				must(t, db.QueryRow("SELECT state FROM sessions WHERE id=?", a.SessionID).Scan(&state))
				if version != 4 || digest != old || tables != 0 || state != "requested" {
					t.Fatal("partial closure migration committed")
				}
				must(t, verifyAudit(ctx, db))
				return
			}
			must(t, e)
			defer reopened.Close()
			engine, e := NewPolicyEngine(reopened, v.engine.config)
			must(t, e)
			batch, e := engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
			must(t, e)
			if len(batch.Items) != 1 || batch.Items[0].SessionID != a.SessionID || batch.Items[0].Reason != "closed" {
				t.Fatal("restart lost unreported closure")
			}
			must(t, engine.AcknowledgeCancellation(ctx, v.connectorConn, CancellationAck{Version: 1, SessionID: a.SessionID}))
			must(t, verifyAudit(ctx, reopened.db))
		})
	}
}

func TestConnectorPolicyHTTPAuthenticatedRoutesAndStrictBodies(t *testing.T) {
	v := newPolicyFixture(t)
	device := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Device}, v.deviceIdentity)
	connector := servePolicy(t, v.engine, PolicyHTTPConfig{Profile: pki.Connector}, v.connectorIdentity)
	var status ConnectorStatus
	device.post(t, "/api/v1/device/check-connector", v.connectorCheck(), &status)
	var snapshot HostingSnapshot
	connector.post(t, "/api/v1/connector/hosting", struct{}{}, &snapshot)
	if len(snapshot.Resources) != 1 || status.Resource.ID != snapshot.Resources[0].Resource.ID {
		t.Fatal("HTTP snapshots disagree on resource")
	}
	var permit Authorization
	connector.post(t, "/api/v1/connector/authorize", v.request(), &permit)
	connector.post(t, "/api/v1/connector/close", SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: 1}, nil)
	var batch CancellationBatch
	connector.post(t, "/api/v1/connector/cancellations", CancellationRequest{Version: 1, Limit: 64}, &batch)
	if len(batch.Items) != 1 {
		t.Fatal("HTTP cancellation was lost")
	}
	connector.post(t, "/api/v1/connector/acknowledge-cancellation", CancellationAck{Version: 1, SessionID: permit.SessionID}, nil)
	for _, tc := range []struct {
		client *policyHTTPFixture
		path   string
		body   any
	}{
		{device, "/api/v1/connector/hosting", struct{}{}},
		{device, "/api/v1/connector/cancellations", CancellationRequest{Version: 1, Limit: 64}},
		{device, "/api/v1/connector/acknowledge-cancellation", CancellationAck{Version: 1, SessionID: permit.SessionID}},
		{connector, "/api/v1/device/check-connector", v.connectorCheck()},
		{connector, "/api/v1/connector/hosting", map[string]any{"ConnectorID": NewID()}},
		{connector, "/api/v1/connector/cancellations", map[string]any{"Version": 1, "Limit": 64, "After": 9999}},
		{connector, "/api/v1/connector/acknowledge-cancellation", map[string]any{"Version": 1, "SessionID": permit.SessionID, "Closed": true}},
		{device, "/api/v1/device/check-connector", map[string]any{"Version": 1, "ResourceID": v.device.f.resource.ID, "Revision": 1, "ConnectorLeafDER": v.connectorLeaf, "Port": 22}},
	} {
		b, e := json.Marshal(tc.body)
		must(t, e)
		req, e := http.NewRequest(http.MethodPost, "https://"+tc.client.host+tc.path, bytes.NewReader(b))
		must(t, e)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Portico-Profile", "connector")
		resp, e := tc.client.client.Do(req)
		must(t, e)
		data, e := io.ReadAll(resp.Body)
		must(t, e)
		must(t, resp.Body.Close())
		if resp.StatusCode != http.StatusForbidden || strings.TrimSpace(string(data)) != `{"error":"request rejected"}` {
			t.Fatal("hostile control request accepted or leaked details")
		}
	}
}

func unrelatedSession(t *testing.T, f fixture) Session {
	t.Helper()
	u := f.user
	u.ID = NewID()
	d := f.device
	d.ID = NewID()
	d.UserID = u.ID
	k := f.connector
	k.ID = NewID()
	i := f.issuer
	i.ID = NewID()
	c := f.cert
	c.ID = NewID()
	c.IssuerID = i.ID
	c.PrincipalID = d.ID
	c.LeafSHA256 = pki.Hash([]byte(c.ID))
	c.SPKISHA256 = pki.Hash([]byte(c.ID + "key"))
	service := f.service
	service.ID = NewID()
	service.IssuerID = i.ID
	service.PrincipalID = k.ID
	service.LeafSHA256 = pki.Hash([]byte(service.ID))
	service.SPKISHA256 = pki.Hash([]byte(service.ID + "key"))
	r := f.resource
	r.ID = NewID()
	r.ConnectorID = k.ID
	g := f.grant
	g.ID = NewID()
	g.UserID = u.ID
	g.DeviceID = d.ID
	g.ResourceID = r.ID
	h := f.host
	h.ID = NewID()
	h.ConnectorID = k.ID
	h.ResourceID = r.ID
	s := f.session
	s.ID = NewID()
	s.DeviceID = d.ID
	s.CertificateID = c.ID
	s.ConnectorCertificateID = service.ID
	s.ResourceID = r.ID
	s.GrantID = g.ID
	s.HostBindingID = h.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		for _, op := range []func() error{func() error { return tx.AddUser(u) }, func() error { return tx.AddDevice(d) }, func() error { return tx.AddConnector(k) }, func() error { return tx.AddIssuer(i) }, func() error { return tx.RegisterCertificate(c) }, func() error { return tx.RegisterCertificate(service) }, func() error { return tx.AddResource(r) }, func() error { return tx.AddGrant(g) }, func() error { return tx.AddHostBinding(h) }, func() error { return tx.RecordSession(s) }} {
			if e := op(); e != nil {
				return e
			}
		}
		return nil
	}))
	return s
}

func TestDisableCancelsOnlyDependentSessions(t *testing.T) {
	for _, kind := range []string{"user", "device", "connector", "issuer", "resource", "grant", "host_binding", "certificate", "connector_certificate"} {
		t.Run(kind, func(t *testing.T) {
			f := seed(t)
			must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.RecordSession(f.session) }))
			other := unrelatedSession(t, f)
			ids := map[string]string{"user": f.user.ID, "device": f.device.ID, "connector": f.connector.ID, "issuer": f.issuer.ID, "resource": f.resource.ID, "grant": f.grant.ID, "host_binding": f.host.ID, "certificate": f.cert.ID, "connector_certificate": f.service.ID}
			operation := kind
			if kind == "connector_certificate" {
				operation = "certificate"
			}
			must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable(operation, ids[kind]) }))
			var affected, unaffected string
			must(t, f.s.db.QueryRow("SELECT state FROM sessions WHERE id=?", f.session.ID).Scan(&affected))
			must(t, f.s.db.QueryRow("SELECT state FROM sessions WHERE id=?", other.ID).Scan(&unaffected))
			if affected != "closed" || unaffected != "requested" {
				t.Fatal("disable missed a dependency or closed unrelated authority")
			}
			must(t, verifyAudit(ctx, f.s.db))
		})
	}
}

func TestGrantCancellationPreservesOtherResourceOnSameConnection(t *testing.T) {
	v := newPolicyFixture(t)
	f := v.device.f
	a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	r := f.resource
	r.ID = NewID()
	g := f.grant
	g.ID = NewID()
	g.ResourceID = r.ID
	h := f.host
	h.ID = NewID()
	h.ResourceID = r.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.AddResource(r); e != nil {
			return e
		}
		if e := tx.AddGrant(g); e != nil {
			return e
		}
		return tx.AddHostBinding(h)
	}))
	request := v.request()
	request.ResourceID = r.ID
	b, e := v.engine.Authorize(ctx, v.connectorConn, request)
	must(t, e)
	b, e = v.engine.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: b.SessionID, Sequence: b.Sequence})
	must(t, e)
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
	if _, e = v.engine.Renew(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: b.SessionID, Sequence: b.Sequence}); e != nil {
		t.Fatal("unrelated resource lost authority on same peer connection")
	}
	batch, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].SessionID != a.SessionID {
		t.Fatal("cancellation widened to other resource")
	}
}

func serveControlClient(t *testing.T, v *policyFixture, profile pki.Profile) (*control.Client, control.ClientConfig) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	root, key := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, root, key, true)
	_, port, e := net.SplitHostPort(ln.Addr().String())
	must(t, e)
	host := "localhost:" + port
	server, e := v.engine.NewHTTPServer(PolicyHTTPConfig{Profile: profile, Host: host, ServerIdentity: serverIdentity})
	must(t, e)
	ended := make(chan error, 1)
	go func() { ended <- server.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, server.Close(ctx))
		if e := <-ended; e != http.ErrServerClosed {
			t.Errorf("control service close: %v", e)
		}
	})
	var identity tls.Certificate
	if profile == pki.Device {
		identity, e = v.device.trust.TLSIdentity(v.deviceIdentity)
	} else {
		identity, e = v.connector.trust.TLSIdentity(v.connectorIdentity)
	}
	must(t, e)
	config := control.ClientConfig{Endpoint: "https://" + host, ServerRootDER: root.Raw, ServerSPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo), Identity: identity, Profile: profile, Timeout: 2 * time.Second, MaxConnections: 2}
	client, e := control.NewClient(config)
	must(t, e)
	t.Cleanup(client.Close)
	return client, config
}

func TestProductionControlClientExercisesLivePolicyLifecycle(t *testing.T) {
	v := newPolicyFixture(t)
	device, _ := serveControlClient(t, v, pki.Device)
	connector, _ := serveControlClient(t, v, pki.Connector)
	status, e := device.CheckConnector(ctx, v.connectorCheck())
	must(t, e)
	snapshot, e := connector.Hosting(ctx)
	must(t, e)
	if len(snapshot.Resources) != 1 || snapshot.Resources[0].Resource.ID != status.Resource.ID {
		t.Fatal("client changed resource identity")
	}
	a, e := connector.Authorize(ctx, v.request())
	must(t, e)
	a, e = connector.Activate(ctx, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: a.Sequence})
	must(t, e)
	a, e = connector.Renew(ctx, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: a.Sequence})
	must(t, e)
	must(t, connector.CloseSession(ctx, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: a.Sequence}))
	batch, e := connector.Cancellations(ctx, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].SessionID != a.SessionID {
		t.Fatal("client lost cancellation")
	}
	must(t, connector.AcknowledgeCancellation(ctx, CancellationAck{Version: 1, SessionID: a.SessionID}))
	batch, e = connector.Cancellations(ctx, CancellationRequest{Version: 1, Limit: 64})
	must(t, e)
	if len(batch.Items) != 0 {
		t.Fatal("client lost closure report")
	}
	if _, e = device.Hosting(ctx); e == nil {
		t.Fatal("device client exposed connector methods")
	}
	if _, e = connector.CheckConnector(ctx, v.connectorCheck()); e == nil {
		t.Fatal("connector client exposed device method")
	}
	must(t, v.device.f.s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.Disable("connector", v.device.f.connector.ID) }))
	if _, e = device.CheckConnector(ctx, v.connectorCheck()); e == nil {
		t.Fatal("client trusted previously valid peer after revocation")
	}
	if _, e = connector.Hosting(ctx); e == nil {
		t.Fatal("client reused revoked outer TLS identity")
	}
	connector.Close()
	if _, e = connector.Hosting(ctx); e == nil {
		t.Fatal("closed control client continued")
	}
}

func TestProductionControlClientRejectsWrongPinsAndRoles(t *testing.T) {
	v := newPolicyFixture(t)
	_, config := serveControlClient(t, v, pki.Connector)
	for _, name := range []string{"pin", "name", "root", "profile", "untrusted_identity"} {
		t.Run(name, func(t *testing.T) {
			c := config
			root, key := testfixture.Root(t)
			switch name {
			case "pin":
				c.ServerSPKI = strings.Repeat("0", 64)
			case "name":
				c.Endpoint = strings.Replace(c.Endpoint, "localhost", "127.0.0.1", 1)
			case "root":
				c.ServerRootDER = root.Raw
			case "profile":
				c.Identity = v.deviceIdentity
			case "untrusted_identity":
				c.Identity = testfixture.TLSIdentity(t, root, key, false)
			}
			client, e := control.NewClient(c)
			must(t, e)
			defer client.Close()
			if _, e = client.Hosting(ctx); e == nil {
				t.Fatal("client crossed pinned TLS/profile boundary")
			}
		})
	}
}
