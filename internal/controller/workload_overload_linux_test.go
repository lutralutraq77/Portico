package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/workload"
)

// PROTO-05 composes actual control, carrier/inner TLS and destination sockets.
// These finite guest load observations do not qualify production Q05 timing.
func TestWorkloadGuestBackpressureQuotasAndReconnectFlood(t *testing.T) {
	requireWorkloadGuest(t)
	t.Run("slow_destination_reader", func(t *testing.T) { workloadBackpressure(t, false) })
	t.Run("slow_client_reader", func(t *testing.T) { workloadBackpressure(t, true) })
	t.Run("global_session_quota", func(t *testing.T) { workloadQuotaFlood(t, false) })
	t.Run("device_session_quota", func(t *testing.T) { workloadQuotaFlood(t, true) })
	t.Run("runtime_reconnect_flood", workloadReconnectFlood)
}

func overloadFixture(t *testing.T, destination func(net.Conn), changes ...func(*workload.ServerConfig, *workload.ClientConfig)) *workloadFixture {
	t.Helper()
	return newWorkloadFixtureWithCarrier(t, destination, func(c *carrier.Config) {
		c.MaxStreams, c.MaxPeerStreams = 16, 8
		c.MaxLifetime = 2 * time.Minute
	}, changes...)
}

type overloadOpen struct {
	raw  *carrier.Conn
	conn *workload.Conn
	err  error
}

func openOverload(v *workloadFixture, call context.Context, transport *carrier.Client) overloadOpen {
	s := overloadOpen{}
	r := v.resource
	s.raw, s.err = transport.Dial(call, r.ConnectorID)
	if s.err == nil {
		s.conn, s.err = v.client.Open(call, s.raw, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
	}
	return s
}

func overloadJoined(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("overload fixture retained a stream or worker")
	}
}

func overloadRuntimeStopped(t *testing.T, cancel context.CancelFunc, done <-chan error, v *workloadFixture) {
	t.Helper()
	cancel()
	select {
	case e := <-done:
		must(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("overloaded connector runtime did not join")
	}
	carrierEventually(t, func() bool {
		s := v.carrier.relay.Stats()
		return s.Streams == 0 && s.Waiting == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0 && v.client.ActiveConnections() == 0 && v.server.Stats() == (workload.Stats{})
	})
}

// Each producer reuses one 32 KiB buffer. A stalled 64 MiB write must make
// progress and then stop below 8 MiB, not enqueue its complete input in memory.
// That ceiling includes TCP/TLS/gRPC buffering and is a fixture observation.
type overloadWriter struct {
	written atomic.Int64
	done    chan struct{}
	err     error
}

func (w *overloadWriter) run(dst io.Writer) {
	defer close(w.done)
	buffer := bytes.Repeat([]byte{0xc7}, 32768)
	for i := 0; i < 2048; i++ {
		n, e := dst.Write(buffer)
		w.written.Add(int64(n))
		if e != nil {
			w.err = e
			return
		}
		if n != len(buffer) {
			w.err = io.ErrShortWrite
			return
		}
	}
}

func (w *overloadWriter) backpressured(t *testing.T) int64 {
	t.Helper()
	deadline, lastProgress := time.Now().Add(5*time.Second), time.Now()
	var previous int64
	for time.Now().Before(deadline) {
		select {
		case <-w.done:
			t.Fatalf("producer ended before cancellation: bytes=%d err=%v", w.written.Load(), w.err)
		default:
		}
		n := w.written.Load()
		if n > 8*1024*1024 {
			t.Fatal("stalled stream exceeded the observed buffering ceiling")
		}
		if n != previous {
			previous, lastProgress = n, time.Now()
		}
		if n >= 32768 && time.Since(lastProgress) >= 250*time.Millisecond {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("producer never established bounded backpressure")
	return 0
}

func workloadBackpressure(t *testing.T, reverse bool) {
	writer := &overloadWriter{done: make(chan struct{})}
	var connectorControl workload.ConnectorControl
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseReader := func() { releaseOnce.Do(func() { close(release) }) }
	v := overloadFixture(t, func(c net.Conn) {
		var mode [1]byte
		if _, e := io.ReadFull(c, mode[:]); e != nil {
			return
		}
		if mode[0] == 0 {
			echoWorkloadDestination(c)
			return
		}
		if mode[0] != 1 {
			t.Error("destination received cross-stream or unknown data")
			return
		}
		tcp := c.(*workloadObservedDestination).Conn.(*net.TCPConn)
		if e := tcp.SetWriteBuffer(4096); e != nil {
			t.Error(e)
			return
		}
		close(entered)
		if reverse {
			writer.run(c)
		} else {
			<-release
			// Only drain after the blocked client writer and server-side copy
			// workers have stopped, so the fixture cannot unblock them first.
			if _, e := io.Copy(io.Discard, c); e != nil && !errors.Is(e, syscall.ECONNRESET) {
				t.Errorf("destination did not observe peer closure: %v", e)
			}
		}
	}, func(s *workload.ServerConfig, _ *workload.ClientConfig) { connectorControl = s.Control })
	t.Cleanup(releaseReader)
	stop, stopped := startConnectorRuntime(t, v, 2)
	opened := make(chan overloadOpen, 2)
	go func() { opened <- openOverload(v, ctx, v.carrier.device) }()
	go func() { opened <- openOverload(v, ctx, v.carrier.device) }()
	// Both opens must claim the two pending bindings before either full
	// authorization path can outlast the relay's idle pair timeout.
	first, second := <-opened, <-opened
	for _, s := range []overloadOpen{first, second} {
		must(t, s.err)
		t.Cleanup(func() { _ = s.conn.Close() })
	}
	slow, healthy := first, second
	_, e := healthy.conn.Write([]byte{0})
	must(t, e)
	runtimeEcho(t, healthy.conn)
	_, e = slow.conn.Write([]byte{1})
	must(t, e)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow destination handler was not reached")
	}
	if !reverse {
		go writer.run(slow.conn)
	}
	t.Cleanup(func() {
		_ = slow.conn.Close()
		releaseReader()
		select {
		case <-writer.done:
		case <-time.After(5 * time.Second):
			t.Error("blocked producer did not join during cleanup")
		}
	})
	buffered := writer.backpressured(t)
	t.Logf("producer established backpressure after %d bytes", buffered)
	runtimeEcho(t, healthy.conn)
	if writer.backpressured(t) != buffered {
		t.Fatal("stalled producer continued buffering after backpressure")
	}
	if reverse {
		// End only this session through actual authenticated control. Its
		// resource remains valid, so the unread client's separate resource
		// checks cannot substitute for observing the terminal carrier.
		must(t, connectorControl.CloseSession(ctx, control.SessionRequest{Version: 1, SessionID: slow.conn.SessionID(), Sequence: 1}))
	} else {
		must(t, slow.conn.Close())
	}
	overloadJoined(t, slow.conn.Done())
	if !reverse {
		overloadJoined(t, writer.done)
	}
	carrierEventually(t, func() bool { return v.server.Stats().Connections == 1 })
	releaseReader()
	overloadJoined(t, writer.done)
	if writer.err == nil {
		t.Fatal("cancellation let the blocked producer finish its full budget")
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 1 })
	runtimeEcho(t, healthy.conn)
	must(t, healthy.conn.Close())
	overloadJoined(t, healthy.conn.Done())
	carrierEventually(t, func() bool { return v.closed.Load() == 2 && v.server.Stats() == (workload.Stats{}) })
	overloadRuntimeStopped(t, stop, stopped, v)
	if v.connections.Load() != 2 {
		t.Fatal("backpressure or cancellation reconnected a destination")
	}
	t.Logf("stalled producer stopped at %d bytes of a 64 MiB budget; independent traffic survived and all handles joined", buffered)
}

type overloadPeaks struct {
	relay   carrier.Stats
	server  int
	client  int
	samples int
}

func monitorOverload(t *testing.T, v *workloadFixture, maxSessions int) func() {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var peaks overloadPeaks
	go func() {
		defer close(done)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			s := v.carrier.relay.Stats()
			w := v.server.Stats()
			peaks.relay.Streams = max(peaks.relay.Streams, s.Streams)
			peaks.relay.Waiting = max(peaks.relay.Waiting, s.Waiting)
			peaks.relay.Connections = max(peaks.relay.Connections, s.Connections)
			peaks.relay.Endpoints = max(peaks.relay.Endpoints, s.Endpoints)
			peaks.relay.Watches = max(peaks.relay.Watches, s.Watches)
			peaks.relay.Workers = max(peaks.relay.Workers, s.Workers)
			peaks.server = max(peaks.server, w.Connections+w.PendingReceipts)
			peaks.client = max(peaks.client, v.client.ActiveConnections())
			peaks.samples++
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	finish := func() {
		once.Do(func() {
			close(stop)
			overloadJoined(t, done)
			if peaks.samples < 2 || peaks.relay.Streams > 16 || peaks.relay.Waiting > 8 || peaks.relay.Connections > 8 || peaks.relay.Endpoints > 16 || peaks.relay.Watches > 16 || peaks.relay.Workers > 64 || peaks.server > maxSessions || peaks.client > 8 {
				t.Errorf("overload exceeded configured capacity or retained worker ceiling: %+v", peaks)
			}
			t.Logf("sampled overload peaks: %+v", peaks)
		})
	}
	t.Cleanup(finish)
	return finish
}

func workloadQuotaFlood(t *testing.T, perDevice bool) {
	maxSessions := 2
	if perDevice {
		maxSessions = 8 // Five total attempts cannot hit this global limit.
	}
	v := overloadFixture(t, echoWorkloadDestination, func(s *workload.ServerConfig, c *workload.ClientConfig) {
		s.MaxSessions, s.MaxDeviceSessions, c.MaxConnections = maxSessions, 2, 8
	})
	finishMonitor := monitorOverload(t, v, maxSessions)
	a, servedA := v.open(t)
	b, servedB := v.open(t)
	runtimeEcho(t, a)
	runtimeEcho(t, b)
	var before int
	must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&before))
	if before != 2 {
		t.Fatal("quota fixture did not establish exactly two live authorizations")
	}
	for round := 0; round < 8; round++ {
		// Fresh outer TLS connections prevent a per-connection counter from
		// substituting for global/per-device workload admission. Prepare all
		// pairs first so denial cannot be an idle pairing timeout.
		type attempt struct {
			device, connector *carrier.Client
			raw, bound        *carrier.Conn
			opened            chan overloadOpen
			served            chan error
		}
		var attempts []attempt
		for i := 0; i < 3; i++ {
			d, e := carrier.NewClient(v.carrier.deviceConfig)
			must(t, e)
			t.Cleanup(func() { _ = d.Close() })
			c, e := carrier.NewClient(v.carrier.connectorConfig)
			must(t, e)
			t.Cleanup(func() { _ = c.Close() })
			f := &carrierFixture{policy: v.carrier.policy, relay: v.carrier.relay, device: d, connector: c}
			raw, bound := f.pair(t, ctx)
			attempts = append(attempts, attempt{d, c, raw, bound, make(chan overloadOpen, 1), make(chan error, 1)})
		}
		carrierEventually(t, func() bool { return v.carrier.relay.Stats().Connections == 8 })
		for _, x := range attempts {
			go func() { x.served <- v.server.Serve(ctx, x.bound) }()
			go func() {
				r := v.resource
				c, e := v.client.Open(ctx, x.raw, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
				x.opened <- overloadOpen{raw: x.raw, conn: c, err: e}
			}()
		}
		for _, x := range attempts {
			select {
			case s := <-x.opened:
				if s.conn != nil {
					_ = s.conn.Close()
				}
				if !errors.Is(s.err, workload.ErrDenied) || s.conn != nil {
					t.Error("excess paired workload open escaped server quota")
				}
			case <-time.After(8 * time.Second):
				t.Fatal("quota rejection did not join the client open")
			}
			select {
			case e := <-x.served:
				if !errors.Is(e, workload.ErrDenied) {
					t.Error("excess server Serve did not reject")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("quota rejection retained server work")
			}
			carrierStopped(t, x.raw, x.bound)
			must(t, x.device.Close())
			must(t, x.connector.Close())
		}
		carrierEventually(t, func() bool {
			return v.client.ActiveConnections() == 2 && v.server.Stats() == (workload.Stats{Connections: 2}) && v.carrier.relay.Stats().Connections == 2
		})
		runtimeEcho(t, a)
		runtimeEcho(t, b)
		var after int
		must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&after))
		if after != before || v.connections.Load() != 2 || v.closed.Load() != 0 {
			t.Fatal("over-quota reconnect created authority/destination or displaced active traffic")
		}
	}
	for _, c := range []*workload.Conn{a, b} {
		must(t, c.Close())
		overloadJoined(t, c.Done())
	}
	for _, served := range []<-chan error{servedA, servedB} {
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Fatal("quota holder did not release server work")
		}
	}
	carrierEventually(t, func() bool { return v.closed.Load() == 2 && v.server.Stats() == (workload.Stats{}) })
	// A successful new authorization proves capacity was actually released.
	fresh, served := v.open(t)
	if fresh.SessionID() == a.SessionID() || fresh.SessionID() == b.SessionID() {
		t.Fatal("quota recovery resumed an old session")
	}
	runtimeEcho(t, fresh)
	must(t, fresh.Close())
	overloadJoined(t, fresh.Done())
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("post-overload stream retained server work")
	}
	carrierEventually(t, func() bool {
		s := v.carrier.relay.Stats()
		return v.closed.Load() == 3 && v.connections.Load() == 3 && v.server.Stats() == (workload.Stats{}) && v.client.ActiveConnections() == 0 && s.Streams == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0
	})
	finishMonitor()
	t.Log("24 excess paired opens over fresh TLS connections denied; both active holders survived; fresh authority succeeded after release")
}

func workloadReconnectFlood(t *testing.T) {
	v := overloadFixture(t, echoWorkloadDestination, func(s *workload.ServerConfig, c *workload.ClientConfig) {
		s.MaxSessions, s.MaxDeviceSessions, c.MaxConnections = 4, 4, 8
	})
	finishMonitor := monitorOverload(t, v, 4)
	stop, stopped := startConnectorRuntime(t, v, 3)
	// Start three opens together, then retain one as independent live traffic.
	initial := make(chan overloadOpen, 3)
	for i := 0; i < 3; i++ {
		go func() { initial <- openOverload(v, ctx, v.carrier.device) }()
	}
	var first []overloadOpen
	for i := 0; i < 3; i++ {
		s := <-initial
		must(t, s.err)
		t.Cleanup(func() { _ = s.conn.Close() })
		first = append(first, s)
	}
	anchor := first[0]
	ids := map[string]bool{anchor.conn.SessionID(): true}
	api := rawCarrier(t, v.carrier.deviceConfig)
	var expected int64 = 3
	for round := 0; round < 8; round++ {
		var active []overloadOpen
		var transports []*carrier.Client
		if round == 0 {
			active = first[1:]
		} else {
			carrierEventually(t, func() bool { return v.carrier.relay.Stats().Waiting == 2 })
			opened := make(chan overloadOpen, 2)
			for i := 0; i < 2; i++ {
				c, e := carrier.NewClient(v.carrier.deviceConfig)
				must(t, e)
				t.Cleanup(func() { _ = c.Close() })
				transports = append(transports, c)
				go func() { opened <- openOverload(v, ctx, c) }()
			}
			for i := 0; i < 2; i++ {
				s := <-opened
				must(t, s.err)
				t.Cleanup(func() { _ = s.conn.Close() })
				active = append(active, s)
			}
			expected += 2
		}
		for i, s := range active {
			if ids[s.conn.SessionID()] {
				t.Fatal("reconnect reused authority")
			}
			ids[s.conn.SessionID()] = true
			payload := bytes.Repeat([]byte{byte(17 + round*2 + i)}, 32769)
			must(t, s.conn.SetDeadline(time.Now().Add(5*time.Second)))
			written := make(chan error, 1)
			go func() { _, e := s.conn.Write(payload); written <- e }()
			got := make([]byte, len(payload))
			_, e := io.ReadFull(s.conn, got)
			must(t, e)
			must(t, <-written)
			if !bytes.Equal(got, payload) {
				t.Fatal("reconnect stream mixed, reordered or replayed bytes")
			}
			must(t, s.conn.SetDeadline(time.Time{}))
		}
		// All three runtime workers are occupied. Raw authenticated requests
		// bypass the honest client's local call cap and require server status.
		admitted := v.carrier.admitted.Load()
		denied := make(chan error, 4)
		for i := 0; i < 4; i++ {
			hello := carrierHello(t, v.resource.ConnectorID)
			go func() {
				call, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				s, e := api.Dial(call)
				if e == nil {
					e = s.Send(hello)
				}
				if e == nil {
					_, e = s.Recv()
				}
				denied <- e
			}()
		}
		for i := 0; i < 4; i++ {
			if e := <-denied; status.Code(e) != codes.PermissionDenied {
				t.Fatalf("excess runtime Dial did not receive server denial: %v", e)
			}
		}
		if v.carrier.admitted.Load() != admitted+4 || v.carrier.relay.Stats().Waiting != 0 || v.connections.Load() != expected {
			t.Fatal("excess runtime request did not reach admission or opened a destination")
		}
		runtimeEcho(t, anchor.conn)
		for i, s := range active {
			if (round+i)%2 == 0 {
				must(t, s.conn.Close())
			} else {
				must(t, s.raw.Close())
			}
			overloadJoined(t, s.conn.Done())
			carrierStopped(t, s.raw)
		}
		for _, c := range transports {
			must(t, c.Close())
		}
		carrierEventually(t, func() bool {
			return v.closed.Load() == expected-1 && v.server.Stats() == (workload.Stats{Connections: 1}) && v.client.ActiveConnections() == 1
		})
		runtimeEcho(t, anchor.conn)
	}
	must(t, anchor.conn.Close())
	overloadJoined(t, anchor.conn.Done())
	carrierEventually(t, func() bool { return v.closed.Load() == expected && v.server.Stats() == (workload.Stats{}) })
	var receipts int
	must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts))
	if receipts != len(ids) || int64(len(ids)) != expected {
		t.Fatal("reconnect stream lost closure receipt or created extra authority")
	}
	overloadRuntimeStopped(t, stop, stopped, v)
	finishMonitor()
	t.Logf("8 reconnect waves: %d distinct destination sessions, 32 explicit excess Dial denials; independent anchor survived, receipts and all stream workers joined", expected)
}
