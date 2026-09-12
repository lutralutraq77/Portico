package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/workload"
)

type isolatedConnector struct {
	connector Connector
	identity  tls.Certificate
	leaf      []byte
	certID    string
	control   *control.Client
}

// Enroll a distinct, enabled principal through the same real issuer and
// activation path. Its control requests use its own actual mTLS leaf.
func secondConnector(t *testing.T, p *policyFixture) *isolatedConnector {
	t.Helper()
	f := p.device.f
	b := &isolatedConnector{connector: f.connector}
	b.connector.ID, b.connector.Name = NewID(), "connector B isolation fixture"
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddConnector(b.connector) }))
	_, b.leaf, b.identity = enrolledPolicyPeer(t, p.connector, b.connector.ID)
	var e error
	b.identity, e = p.connector.trust.TLSIdentity(b.identity)
	must(t, e)
	must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(b.leaf)).Scan(&b.certID))
	_, config := serveControlClient(t, p, pki.Connector)
	config.Identity = b.identity
	b.control, e = control.NewClient(config)
	must(t, e)
	t.Cleanup(b.control.Close)
	return b
}

func connectorResource(t *testing.T, p *policyFixture, b *isolatedConnector, template Resource, bind bool) Resource {
	t.Helper()
	f := p.device.f
	r := template
	r.ID, r.ConnectorID, r.Name = NewID(), b.connector.ID, "connector B resource"
	g, h := f.grant, f.host
	g.ID, g.ResourceID = NewID(), r.ID
	h.ID, h.ResourceID, h.ConnectorID = NewID(), r.ID, b.connector.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.AddResource(r); e != nil {
			return e
		}
		if e := tx.AddGrant(g); e != nil {
			return e
		}
		if bind {
			return tx.AddHostBinding(h)
		}
		return nil
	}))
	return r
}

// CONN-03: exercise the HTTP surface, not an injected principal or a direct
// engine call. The positive B lease makes authentication failure a bad oracle.
func TestConnectorControlCrossScopeIsolation(t *testing.T) {
	p := newPolicyFixture(t)
	f := p.device.f
	a, _ := serveControlClient(t, p, pki.Connector)
	b := secondConnector(t, p)
	r := connectorResource(t, p, b, f.resource, true)
	// Keep a real superseded revision in storage, rather than testing only a
	// nonexistent revision. Its old grant and binding must not authorize it.
	r.Revision++
	g, h := f.grant, f.host
	g.ID, g.ResourceID, g.Revision = NewID(), r.ID, r.Revision
	h.ID, h.ResourceID, h.ConnectorID, h.Revision = NewID(), r.ID, b.connector.ID, r.Revision
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.ReviseResource(r.Revision-1, r); e != nil {
			return e
		}
		if e := tx.AddGrant(g); e != nil {
			return e
		}
		return tx.AddHostBinding(h)
	}))
	hosting, e := b.control.Hosting(ctx)
	must(t, e)
	if hosting.ConnectorID != b.connector.ID || hosting.ConnectorCertificateID != b.certID || len(hosting.Resources) != 1 || hosting.Resources[0].Resource.ID != r.ID {
		t.Fatal("B hosting exposed another connector's resource or identity")
	}
	request := control.AuthorizeRequest{Version: 1, ClientLeafDER: p.deviceLeaf, ResourceID: r.ID, Revision: r.Revision}
	owned, e := b.control.Authorize(ctx, request)
	must(t, e)
	if owned.ConnectorID != b.connector.ID || owned.ConnectorCertificateID != b.certID || owned.Resource.ID != r.ID {
		t.Fatal("B positive authorization has wrong ownership")
	}
	owned, e = b.control.Activate(ctx, control.SessionRequest{Version: 1, SessionID: owned.SessionID, Sequence: owned.Sequence})
	must(t, e)
	owned, e = b.control.Renew(ctx, control.SessionRequest{Version: 1, SessionID: owned.SessionID, Sequence: owned.Sequence})
	must(t, e)
	must(t, b.control.CloseSession(ctx, control.SessionRequest{Version: 1, SessionID: owned.SessionID, Sequence: owned.Sequence}))
	must(t, b.control.AcknowledgeCancellation(ctx, control.CancellationAck{Version: 1, SessionID: owned.SessionID}))

	var sessionsBefore, sessionsAfter int
	must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&sessionsBefore))
	for _, tc := range []struct {
		name     string
		resource Resource
		revision int64
	}{
		{"another_connector", f.resource, f.resource.Revision},
		{"another_connector_revision", f.resource, f.resource.Revision + 1},
		{"own_superseded_revision", r, r.Revision - 1},
		{"own_unapproved_revision", r, r.Revision + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := request
			bad.ResourceID, bad.Revision = tc.resource.ID, tc.revision
			if _, e := b.control.Authorize(ctx, bad); e == nil {
				t.Fatal("cross-scope authorization succeeded")
			}
		})
	}
	must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&sessionsAfter))
	if sessionsBefore != sessionsAfter {
		t.Fatal("denied authorization created a session")
	}
	lease, e := a.Authorize(ctx, p.request())
	must(t, e)
	type sessionState struct {
		state, authority        string
		sequence, until         int64
		cancellations, receipts int
	}
	readState := func() sessionState {
		var s sessionState
		must(t, f.s.db.QueryRow(`SELECT s.state,a.state,a.lease_sequence,a.lease_until,
 (SELECT count(*) FROM session_cancellations WHERE session_id=s.id),
 (SELECT count(*) FROM session_closure_receipts WHERE session_id=s.id)
 FROM sessions s JOIN authorized_sessions a ON a.id=s.id WHERE s.id=?`, lease.SessionID).Scan(&s.state, &s.authority, &s.sequence, &s.until, &s.cancellations, &s.receipts))
		return s
	}
	denyUnchanged := func(t *testing.T, action func() error) {
		t.Helper()
		before := readState()
		if e := action(); e == nil {
			t.Fatal("B modified A's session")
		}
		if after := readState(); after != before {
			t.Fatalf("denial changed A's state: before=%+v after=%+v", before, after)
		}
	}
	sr := control.SessionRequest{Version: 1, SessionID: lease.SessionID, Sequence: lease.Sequence}
	t.Run("unrelated_activation", func(t *testing.T) {
		denyUnchanged(t, func() error { _, e := b.control.Activate(ctx, sr); return e })
	})
	lease, e = a.Activate(ctx, sr)
	must(t, e)
	sr.Sequence = lease.Sequence
	t.Run("unrelated_renewal", func(t *testing.T) {
		denyUnchanged(t, func() error { _, e := b.control.Renew(ctx, sr); return e })
	})
	t.Run("unrelated_close", func(t *testing.T) {
		denyUnchanged(t, func() error { return b.control.CloseSession(ctx, sr) })
	})
	lease, e = a.Renew(ctx, sr)
	must(t, e)
	sr.Sequence = lease.Sequence
	must(t, a.CloseSession(ctx, sr))
	t.Run("unrelated_receipt", func(t *testing.T) {
		denyUnchanged(t, func() error {
			return b.control.AcknowledgeCancellation(ctx, control.CancellationAck{Version: 1, SessionID: lease.SessionID})
		})
	})
	selection := control.CancellationRequest{Version: 1, Limit: 64, SessionIDs: []string{lease.SessionID}}
	batch, e := b.control.Cancellations(ctx, selection)
	must(t, e)
	if len(batch.Items) != 0 || batch.ConnectorCertificateID != b.certID {
		t.Fatal("B selection exposed A's cancellation")
	}
	batch, e = a.Cancellations(ctx, selection)
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].SessionID != lease.SessionID {
		t.Fatal("A lost its own cancellation after hostile requests")
	}
	must(t, a.AcknowledgeCancellation(ctx, control.CancellationAck{Version: 1, SessionID: lease.SessionID}))
	must(t, verifyAudit(ctx, f.s.db))
	t.Log("CONN-03: actual B mTLS denied cross-connector/revision/session requests; A state unchanged; both owners completed their own lifecycle")
}

func pairConnector(t *testing.T, v *carrierFixture, client *carrier.Client, id string) (*carrier.Conn, *carrier.Conn) {
	t.Helper()
	call, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	type result struct {
		conn *carrier.Conn
		err  error
	}
	bound := make(chan result, 1)
	go func() { c, e := client.Bind(call, id); bound <- result{c, e} }()
	carrierEventually(t, func() bool { return v.relay.Stats().Waiting == 1 })
	device, e := v.device.Dial(call, id)
	must(t, e)
	t.Cleanup(func() { _ = device.Close() })
	select {
	case r := <-bound:
		must(t, r.err)
		t.Cleanup(func() { _ = r.conn.Close() })
		return device, r.conn
	case <-time.After(5 * time.Second):
		t.Fatal("connector pair did not join")
	}
	return nil, nil
}

// Bypass the honest device's CheckConnector request, while still authenticating
// both real inner TLS leaves. A hosting denial must happen at the server too.
func hostileWorkloadOpenDenied(t *testing.T, v *workloadFixture, transport *carrier.Client, server *workload.Server, id string, leaf []byte, resource Resource) {
	t.Helper()
	device, connector := pairConnector(t, v.carrier, transport, id)
	hostileInnerOpenDenied(t, v, device, connector, server, id, leaf, resource)
	carrierStopped(t, device, connector)
}

func hostileInnerOpenDenied(t *testing.T, v *workloadFixture, device, connector net.Conn, server *workload.Server, id string, leaf []byte, resource Resource) {
	t.Helper()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, connector) }()
	config, e := v.carrier.policy.connector.trust.ConnectorClientTLS(v.carrier.deviceConfig.Identity, id)
	must(t, e)
	inner := tls.Client(device, config)
	t.Cleanup(func() { _ = inner.Close() })
	must(t, inner.SetDeadline(time.Now().Add(5*time.Second)))
	must(t, inner.HandshakeContext(ctx))
	if !bytes.Equal(inner.ConnectionState().PeerCertificates[0].Raw, leaf) {
		t.Fatal("hostile request reached a different connector identity")
	}
	request := struct {
		Version    int
		ResourceID string
		Revision   int64
	}{1, resource.ID, resource.Revision}
	body, e := json.Marshal(request)
	must(t, e)
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	n, e := inner.Write(frame)
	must(t, e)
	if n != len(frame) {
		t.Fatal("hostile request was not fully delivered")
	}
	var response [1]byte
	if n, e = inner.Read(response[:]); n != 0 || e == nil {
		t.Fatal("unassigned workload returned application protocol data")
	}
	select {
	case e := <-served:
		if e == nil {
			t.Fatal("unassigned workload Serve succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("denied workload did not join")
	}
	_ = inner.Close()
	carrierEventually(t, func() bool { return server.Stats() == (workload.Stats{}) })
}

// CONN-01: real TCP dials run only in the explicit NIC-less Linux guest. The
// malicious local approval list alone must never create remote authority.
func TestWorkloadGuestTwoConnectorHostingIsolation(t *testing.T) {
	v := newWorkloadFixture(t)
	p, f := v.carrier.policy, v.carrier.policy.device.f
	b := secondConnector(t, p)
	r := connectorResource(t, p, b, v.resource, false)
	config := v.carrier.connectorConfig
	config.Identity = b.identity
	bCarrier, e := carrier.NewClient(config)
	must(t, e)
	t.Cleanup(func() { _ = bCarrier.Close() })
	approved := func(r Resource) workload.Destination {
		return workload.Destination{ResourceID: r.ID, Revision: r.Revision, Address: r.Address, Port: r.Port, Protocol: r.Protocol}
	}
	bServer, e := workload.NewServer(ctx, workload.ServerConfig{
		Control: b.control, Devices: p.device.trust, Connectors: p.connector.trust,
		Identity: b.identity, CertificateID: b.certID,
		Approved:          []workload.Destination{approved(v.resource), approved(r)},
		ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
		MaxSessions:       4, MaxDeviceSessions: 4, OperationTimeout: 5 * time.Second, IdleTimeout: time.Minute,
		ClockHealth: func() (time.Duration, error) { return 20 * time.Millisecond, nil },
	})
	must(t, e)
	t.Cleanup(bServer.Close)
	hosting, e := b.control.Hosting(ctx)
	must(t, e)
	if hosting.ConnectorID != b.connector.ID || len(hosting.Resources) != 0 {
		t.Fatal("B advertised a resource without its own HostBinding")
	}
	t.Run("B_cannot_bind_as_A", func(t *testing.T) {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		api := rawCarrier(t, config)
		stream, e := api.Bind(call)
		must(t, e)
		admitted := v.carrier.admitted.Load()
		must(t, stream.Send(carrierHello(t, f.connector.ID)))
		bound := make(chan error, 1)
		go func() {
			_, e := stream.Recv()
			bound <- e
		}()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case e := <-bound:
				if status.Code(e) != codes.PermissionDenied || call.Err() != nil || v.carrier.admitted.Load() != admitted+1 {
					t.Fatal("spoofed Bind did not explicitly reject the authenticated B identity")
				}
				return
			case <-tick.C:
				if v.carrier.relay.Stats().Waiting != 0 {
					t.Fatal("spoofed Bind was admitted to the pairing queue")
				}
			case <-call.Done():
				t.Fatal("spoofed Bind did not receive server rejection")
			}
		}
	})
	carrierEventually(t, func() bool { return bCarrier.ActiveStreams() == 0 && v.carrier.relay.Stats().Waiting == 0 })
	closeEcho := func(c *workload.Conn, served <-chan error, payload string) {
		t.Helper()
		must(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		_, e := c.Write([]byte(payload))
		must(t, e)
		got := make([]byte, len(payload))
		_, e = io.ReadFull(c, got)
		must(t, e)
		if string(got) != payload {
			t.Fatal("positive connector echo changed payload")
		}
		must(t, c.Close())
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatal("positive connector workload did not join")
		}
	}
	aConn, aServed := v.open(t)
	closeEcho(aConn, aServed, "A assigned resource")
	carrierEventually(t, func() bool { return v.closed.Load() == 1 && v.server.Stats() == (workload.Stats{}) })
	t.Run("B_cannot_serve_A", func(t *testing.T) {
		hostileWorkloadOpenDenied(t, v, bCarrier, bServer, b.connector.ID, b.leaf, v.resource)
	})
	t.Run("B_requires_host_binding", func(t *testing.T) {
		hostileWorkloadOpenDenied(t, v, bCarrier, bServer, b.connector.ID, b.leaf, r)
	})
	if v.connections.Load() != 1 || v.received.Load() != int64(len("A assigned resource")) {
		t.Fatal("B denial opened destination or forwarded bytes")
	}
	h := f.host
	h.ID, h.ResourceID, h.ConnectorID = NewID(), r.ID, b.connector.ID
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.AddHostBinding(h) }))
	hosting, e = b.control.Hosting(ctx)
	must(t, e)
	if len(hosting.Resources) != 1 || hosting.Resources[0].Resource.ID != r.ID || hosting.Resources[0].HostBindingID != h.ID {
		t.Fatal("B hosting did not expose exactly its newly assigned binding")
	}
	device, connector := pairConnector(t, v.carrier, bCarrier, b.connector.ID)
	served := make(chan error, 1)
	go func() { served <- bServer.Serve(ctx, connector) }()
	c, e := v.client.Open(ctx, device, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
	must(t, e)
	t.Cleanup(func() { _ = c.Close() })
	closeEcho(c, served, "B newly assigned resource")
	carrierStopped(t, device, connector)
	carrierEventually(t, func() bool { return v.closed.Load() == 2 && bServer.Stats() == (workload.Stats{}) })
	var aBinding string
	must(t, f.s.db.QueryRow("SELECT id FROM host_bindings WHERE resource_id=?", v.resource.ID).Scan(&aBinding))
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("host_binding", aBinding) }))
	t.Run("A_requires_live_host_binding", func(t *testing.T) {
		hostileWorkloadOpenDenied(t, v, v.carrier.connector, v.server, f.connector.ID, p.connectorLeaf, v.resource)
	})
	if v.connections.Load() != 2 || v.closed.Load() != 2 || v.received.Load() != int64(len("A assigned resource")+len("B newly assigned resource")) {
		t.Fatal("denied hosting changed destination counters")
	}
	carrierEventually(t, func() bool {
		s := v.carrier.relay.Stats()
		return s.Streams == 0 && s.Waiting == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0
	})
	must(t, verifyAudit(ctx, f.s.db))
	t.Log("CONN-01: two actual connector identities; spoofed Bind and unassigned opens denied; exactly two authorized destination connections joined, no denied bytes")
}
