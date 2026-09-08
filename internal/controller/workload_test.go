package controller

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/workload"
)

func requireWorkloadGuest(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getenv("PORTICO_ISOLATED_VM") != "1" {
		t.Skip("requires NIC-less guest with explicit fixture address")
	}
	marker, e := os.ReadFile("/portico-isolated-fixture")
	if e != nil || string(marker) != "192.0.2.10\n" {
		t.Fatal("missing isolated guest marker")
	}
	interfaces, e := net.Interfaces()
	must(t, e)
	for _, v := range interfaces {
		if v.Flags&net.FlagLoopback == 0 {
			t.Fatal("destination test guest has a non-loopback interface")
		}
	}
}

type workloadFixture struct {
	carrier                       *carrierFixture
	server                        *workload.Server
	client                        *workload.Client
	resource                      Resource
	grant                         Grant
	listener                      net.Listener
	connections, closed, received atomic.Int64
	workers                       sync.WaitGroup
}

func newWorkloadFixture(t *testing.T, changes ...func(*workload.ServerConfig, *workload.ClientConfig)) *workloadFixture {
	t.Helper()
	return newWorkloadFixtureWithDestination(t, echoWorkloadDestination, changes...)
}

type workloadObservedDestination struct {
	net.Conn
	received *atomic.Int64
}

func (c *workloadObservedDestination) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.received.Add(int64(n))
	return n, e
}

func echoWorkloadDestination(c net.Conn) {
	buffer := make([]byte, 32768)
	for {
		n, e := c.Read(buffer)
		if n > 0 {
			if _, we := c.Write(buffer[:n]); we != nil {
				return
			}
		}
		if e != nil {
			return
		}
	}
}

func newWorkloadFixtureWithDestination(t *testing.T, destination func(net.Conn), changes ...func(*workload.ServerConfig, *workload.ClientConfig)) *workloadFixture {
	t.Helper()
	return newWorkloadFixtureWithCarrier(t, destination, nil, changes...)
}

func newWorkloadFixtureWithCarrier(t *testing.T, destination func(net.Conn), carrierChange func(*carrier.Config), changes ...func(*workload.ServerConfig, *workload.ClientConfig)) *workloadFixture {
	t.Helper()
	requireWorkloadGuest(t)
	if destination == nil {
		t.Fatal("missing destination fixture handler")
	}
	v := &workloadFixture{carrier: newCarrierFixture(t, carrierChange)}
	p := v.carrier.policy
	f := p.device.f
	f.s.now = time.Now
	p.engine.config.LeaseLifetime = 3 * time.Second
	p.engine.config.ActivationLifetime = 2 * time.Second
	ln, e := net.Listen("tcp", "192.0.2.10:0")
	must(t, e)
	v.listener = ln
	r := f.resource
	r.ID = NewID()
	r.Address = "192.0.2.10"
	r.Port = ln.Addr().(*net.TCPAddr).Port
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
	v.resource = r
	v.grant = g
	controlConnector, _ := serveControlClient(t, p, pki.Connector)
	controlDevice, _ := serveControlClient(t, p, pki.Device)
	var cert string
	must(t, f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(p.connectorLeaf)).Scan(&cert))
	health := func() (time.Duration, error) { return 20 * time.Millisecond, nil }
	sc := workload.ServerConfig{Control: controlConnector, Devices: p.device.trust, Connectors: p.connector.trust, Identity: p.connectorIdentity, CertificateID: cert, Approved: []workload.Destination{{ResourceID: r.ID, Revision: r.Revision, Address: r.Address, Port: r.Port, Protocol: r.Protocol}}, ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}, MaxSessions: 4, MaxDeviceSessions: 4, OperationTimeout: 5 * time.Second, IdleTimeout: time.Minute, ClockHealth: health}
	cc := workload.ClientConfig{Control: controlDevice, Devices: p.device.trust, Connectors: p.connector.trust, Identity: p.deviceIdentity, MaxConnections: 4, OperationTimeout: 5 * time.Second, IdleTimeout: time.Minute, ClockHealth: health}
	for _, change := range changes {
		change(&sc, &cc)
	}
	v.server, e = workload.NewServer(ctx, sc)
	must(t, e)
	v.client, e = workload.NewClient(ctx, cc)
	must(t, e)
	v.workers.Add(1)
	go func() {
		defer v.workers.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			v.connections.Add(1)
			v.workers.Add(1)
			go func() {
				defer v.workers.Done()
				defer func() {
					_ = c.Close()
					v.closed.Add(1)
				}()
				destination(&workloadObservedDestination{Conn: c, received: &v.received})
			}()
		}
	}()
	t.Cleanup(func() { v.client.Close(); v.server.Close(); _ = ln.Close(); v.workers.Wait() })
	return v
}
func (v *workloadFixture) open(t *testing.T) (*workload.Conn, <-chan error) {
	t.Helper()
	c, served, e := v.tryOpen(t)
	must(t, e)
	t.Cleanup(func() { _ = c.Close() })
	return c, served
}
func (v *workloadFixture) tryOpen(t *testing.T) (*workload.Conn, <-chan error, error) {
	t.Helper()
	client, server := v.carrier.pair(t, ctx)
	served := make(chan error, 1)
	go func() { served <- v.server.Serve(ctx, server) }()
	r := v.resource
	c, e := v.client.Open(ctx, client, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
	return c, served, e
}

type workloadControlHooks struct {
	workload.ConnectorControl
	activate      func(context.Context, control.SessionRequest) (control.Authorization, error)
	renew         func(context.Context, control.SessionRequest) (control.Authorization, error)
	cancellations func(context.Context, control.CancellationRequest) (control.CancellationBatch, error)
}

func (h *workloadControlHooks) Activate(ctx context.Context, r control.SessionRequest) (control.Authorization, error) {
	if h.activate != nil {
		return h.activate(ctx, r)
	}
	return h.ConnectorControl.Activate(ctx, r)
}
func (h *workloadControlHooks) Renew(ctx context.Context, r control.SessionRequest) (control.Authorization, error) {
	if h.renew != nil {
		return h.renew(ctx, r)
	}
	return h.ConnectorControl.Renew(ctx, r)
}
func (h *workloadControlHooks) Cancellations(ctx context.Context, r control.CancellationRequest) (control.CancellationBatch, error) {
	if h.cancellations != nil {
		return h.cancellations(ctx, r)
	}
	return h.ConnectorControl.Cancellations(ctx, r)
}

func TestWorkloadGuestNoDialWithoutExactLocalAndLiveAuthority(t *testing.T) {
	for _, name := range []string{"local_port", "local_address", "local_revision", "grant", "host_binding", "resource"} {
		t.Run(name, func(t *testing.T) {
			v := newWorkloadFixture(t, func(s *workload.ServerConfig, _ *workload.ClientConfig) {
				switch name {
				case "local_port":
					if s.Approved[0].Port == 65535 {
						s.Approved[0].Port--
					} else {
						s.Approved[0].Port++
					}
				case "local_address":
					s.Approved[0].Address = "192.0.2.11"
				case "local_revision":
					s.Approved[0].Revision++
				}
			})
			f := v.carrier.policy.device.f
			if name == "grant" || name == "resource" || name == "host_binding" {
				id := v.grant.ID
				if name == "resource" {
					id = v.resource.ID
				}
				if name == "host_binding" {
					must(t, f.s.db.QueryRow("SELECT id FROM host_bindings WHERE resource_id=?", v.resource.ID).Scan(&id))
				}
				must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable(name, id) }))
			}
			c, served, e := v.tryOpen(t)
			if e == nil {
				_ = c.Close()
				t.Fatal("unapproved access opened")
			}
			select {
			case <-served:
			case <-time.After(5 * time.Second):
				t.Fatal("denial did not join")
			}
			if v.connections.Load() != 0 || v.received.Load() != 0 {
				t.Fatal("denied access reached destination")
			}
			if v.server.Stats().Connections != 0 {
				t.Fatal("denial retained active connection")
			}
		})
	}
}

func TestWorkloadGuestActivationDenialForwardsNoBytes(t *testing.T) {
	v := newWorkloadFixture(t, func(s *workload.ServerConfig, _ *workload.ClientConfig) {
		s.Control = &workloadControlHooks{ConnectorControl: s.Control, activate: func(context.Context, control.SessionRequest) (control.Authorization, error) {
			return control.Authorization{}, workload.ErrDenied
		}}
	})
	c, served, e := v.tryOpen(t)
	if e == nil {
		_ = c.Close()
		t.Fatal("activation denial opened workload")
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("activation denial left workers alive")
	}
	carrierEventually(t, func() bool { return v.connections.Load() == 1 && v.closed.Load() == 1 })
	if v.received.Load() != 0 {
		t.Fatal("application bytes preceded activation")
	}
	carrierEventually(t, func() bool { return v.server.Stats().PendingReceipts == 0 })
}

func TestWorkloadGuestDelayedRenewalCannotExtendOldLease(t *testing.T) {
	renewStarted := make(chan time.Time, 1)
	var partition atomic.Bool
	partition.Store(true)
	v := newWorkloadFixture(t, func(s *workload.ServerConfig, _ *workload.ClientConfig) {
		base := s.Control
		s.Control = &workloadControlHooks{ConnectorControl: base,
			renew: func(call context.Context, r control.SessionRequest) (control.Authorization, error) {
				start := time.Now()
				a, e := base.Renew(call, r)
				if e != nil {
					return a, e
				}
				renewStarted <- start
				<-call.Done()
				// A delayed successful response is deliberately returned after
				// local cancellation to exercise the independent expiry guard.
				return a, nil
			},
			cancellations: func(call context.Context, r control.CancellationRequest) (control.CancellationBatch, error) {
				if partition.Load() {
					<-call.Done()
					return control.CancellationBatch{}, call.Err()
				}
				return base.Cancellations(call, r)
			},
		}
	})
	c, served := v.open(t)
	_, e := c.Write([]byte("ping"))
	must(t, e)
	got := make([]byte, 4)
	_, e = io.ReadFull(c, got)
	must(t, e)
	var start time.Time
	select {
	case start = <-renewStarted:
	case <-time.After(4 * time.Second):
		t.Fatal("renewal never reached delay fixture")
	}
	select {
	case <-served:
	case <-time.After(4 * time.Second):
		t.Fatal("delayed response extended expired lease")
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 1 })
	if _, e = c.Write([]byte("late")); e == nil {
		t.Fatal("expired session revived")
	}
	t.Logf("destination closed %s after withheld renewal began", time.Since(start))
	partition.Store(false)
}

type workloadHeldDone struct {
	net.Conn
	done <-chan struct{}
}

func (c *workloadHeldDone) Done() <-chan struct{} { return c.done }

func TestWorkloadGuestReceiptWaitsForCarrierWorkers(t *testing.T) {
	v := newWorkloadFixture(t)
	client, raw := v.carrier.pair(t, ctx)
	gate := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	served := make(chan error, 1)
	go func() { served <- v.server.Serve(ctx, &workloadHeldDone{Conn: raw, done: gate}) }()
	r := v.resource
	c, e := v.client.Open(ctx, client, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
	must(t, e)
	t.Cleanup(func() { _ = c.Close() })
	f := v.carrier.policy.device.f
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", v.grant.ID) }))
	carrierEventually(t, func() bool { return v.closed.Load() == 1 })
	// Destination closure alone is insufficient: the underlying carrier must
	// independently signal that all of its workers have joined.
	for i := 0; i < 5; i++ {
		var receipts int
		must(t, f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts WHERE session_id=?", c.SessionID()).Scan(&receipts))
		if receipts != 0 {
			t.Fatal("receipt preceded carrier worker completion")
		}
		select {
		case <-served:
			t.Fatal("Serve returned before carrier workers joined")
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	select {
	case <-raw.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("real carrier did not close")
	}
	release.Do(func() { close(gate) })
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not finish after carrier completion")
	}
	carrierEventually(t, func() bool {
		var receipts int
		return f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts WHERE session_id=?", c.SessionID()).Scan(&receipts) == nil && receipts == 1
	})
}
func TestWorkloadGuestDestinationAndRevocation(t *testing.T) {
	v := newWorkloadFixture(t)
	c, served := v.open(t)
	payload := bytes.Repeat([]byte("resource payload "), 8192)
	wrote := make(chan error, 1)
	go func() { _, e := c.Write(payload); wrote <- e }()
	got := make([]byte, len(payload))
	_, e := io.ReadFull(c, got)
	must(t, e)
	must(t, <-wrote)
	if !bytes.Equal(payload, got) || v.connections.Load() != 1 || v.received.Load() != int64(len(payload)) {
		t.Fatal("exact destination byte counts differ")
	}
	f := v.carrier.policy.device.f
	start := time.Now()
	must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", v.grant.ID) }))
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation left forwarding alive")
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 1 })
	var reports int
	carrierEventually(t, func() bool {
		e := f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts WHERE session_id=?", c.SessionID()).Scan(&reports)
		return e == nil && reports == 1
	})
	if v.closed.Load() != 1 {
		t.Fatal("receipt preceded destination closure")
	}
	t.Logf("destination closed and receipt observed after %s", time.Since(start))
	if _, e = c.Write([]byte("after revoke")); e == nil {
		t.Fatal("revoked client forwarded")
	}
	if v.connections.Load() != 1 {
		t.Fatal("revocation dialed a replacement destination")
	}
}
func TestWorkloadGuestHalfCloseAndRenewal(t *testing.T) {
	v := newWorkloadFixture(t)
	c, served := v.open(t)
	for i := 0; i < 5; i++ {
		_, e := c.Write([]byte("ping"))
		must(t, e)
		got := make([]byte, 4)
		_, e = io.ReadFull(c, got)
		must(t, e)
		if string(got) != "ping" {
			t.Fatal("echo changed")
		}
		time.Sleep(650 * time.Millisecond)
	}
	must(t, c.CloseWrite())
	_, e := io.ReadAll(c)
	must(t, e)
	select {
	case e := <-served:
		must(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("half-close did not finish")
	}
	f := v.carrier.policy.device.f
	var sequence int64
	must(t, f.s.db.QueryRow("SELECT lease_sequence FROM authorized_sessions WHERE id=?", c.SessionID()).Scan(&sequence))
	if sequence < 3 {
		t.Fatal("traffic never survived a lease renewal")
	}
	carrierEventually(t, func() bool { return v.server.Stats().PendingReceipts == 0 && v.server.Stats().Connections == 0 })
}
