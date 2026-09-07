package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"portico.local/portico/internal/carrier"
	pb "portico.local/portico/internal/carrierpb"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type carrierFixture struct {
	policy                        *policyFixture
	relay                         *carrier.Relay
	device, connector             *carrier.Client
	deviceConfig, connectorConfig carrier.ClientConfig
	admitted                      atomic.Int64
}

func newCarrierFixture(t *testing.T, change func(*carrier.Config)) *carrierFixture {
	t.Helper()
	f := &carrierFixture{policy: newPolicyFixture(t)}
	p := f.policy
	root, key := testfixture.Root(t)
	server := testfixture.TLSIdentity(t, root, key, true)
	c := carrier.Config{ServerIdentity: server, Devices: p.device.trust, Connectors: p.connector.trust,
		MaxConnections: 8, MaxStreams: 8, MaxPeerStreams: 4,
		HelloTimeout: time.Second, PairTimeout: 2 * time.Second, MaxLifetime: 20 * time.Second}
	c.Admit = func(ctx context.Context, v pki.Credential, der []byte) error {
		trust := p.device.trust
		if v.Profile == pki.Connector {
			trust = p.connector.trust
		}
		e := p.device.f.s.Update(ctx, trust.IssuerID(), func(tx *Tx) error {
			peer, e := tx.peer(trust, der, false)
			if e != nil {
				return e
			}
			if peer.credential.PrincipalID != v.PrincipalID {
				return ErrDenied
			}
			return nil
		})
		if e == nil {
			f.admitted.Add(1)
		}
		return e
	}
	if change != nil {
		change(&c)
	}
	var e error
	f.relay, e = carrier.New(c)
	must(t, e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	served := make(chan error, 1)
	go func() { served <- f.relay.Serve(listener) }()
	t.Cleanup(func() {
		f.relay.Close()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("relay Serve did not stop")
		}
		if s := f.relay.Stats(); s.Streams != 0 || s.Waiting != 0 || s.Workers != 0 || s.Connections != 0 || s.Endpoints != 0 || s.Watches != 0 {
			t.Errorf("relay leaked handles: %+v", s)
		}
	})
	identity, e := p.device.trust.TLSIdentity(p.deviceIdentity)
	must(t, e)
	open := 3 * time.Second
	if c.MaxLifetime < open {
		open = c.MaxLifetime
	}
	f.deviceConfig = carrier.ClientConfig{Endpoint: "https://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
		ServerRootDER: root.Raw, ServerSPKI: pki.Hash(server.Leaf.RawSubjectPublicKeyInfo), Identity: identity,
		OpenTimeout: open, MaxLifetime: c.MaxLifetime, MaxStreams: 8}
	f.connectorConfig = f.deviceConfig
	f.connectorConfig.Identity, e = p.connector.trust.TLSIdentity(p.connectorIdentity)
	must(t, e)
	f.device, e = carrier.NewClient(f.deviceConfig)
	must(t, e)
	t.Cleanup(func() { _ = f.device.Close() })
	f.connector, e = carrier.NewClient(f.connectorConfig)
	must(t, e)
	t.Cleanup(func() { _ = f.connector.Close() })
	return f
}

func carrierEventually(t *testing.T, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatal("carrier condition did not converge")
		case <-tick.C:
		}
	}
}

func carrierStopped(t *testing.T, conns ...*carrier.Conn) {
	t.Helper()
	for _, c := range conns {
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("carrier pumps did not stop")
		}
	}
}

func (f *carrierFixture) pair(t *testing.T, ctx context.Context) (*carrier.Conn, *carrier.Conn) {
	t.Helper()
	type result struct {
		conn *carrier.Conn
		err  error
	}
	bound := make(chan result, 1)
	id := f.policy.device.f.connector.ID
	go func() { c, e := f.connector.Bind(ctx, id); bound <- result{c, e} }()
	carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
	client, e := f.device.Dial(ctx, id)
	must(t, e)
	t.Cleanup(func() { _ = client.Close() })
	select {
	case r := <-bound:
		must(t, r.err)
		t.Cleanup(func() { _ = r.conn.Close() })
		return client, r.conn
	case <-time.After(5 * time.Second):
		t.Fatal("paired Bind did not return")
	}
	return nil, nil
}

// Record the stream immediately below inner TLS. This observes precisely the
// DATA bytes available to the relay, without exposing a production logging hook.
type recordedCarrier struct {
	net.Conn
	mu   sync.Mutex
	data []byte
}

func (r *recordedCarrier) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.data = append(r.data, b...)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func TestCarrierInnerTLSBidirectionalAndHalfClose(t *testing.T) {
	f := newCarrierFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, b := f.pair(t, ctx)
	ra, rb := &recordedCarrier{Conn: a}, &recordedCarrier{Conn: b}
	cc, e := f.policy.connector.trust.ConnectorClientTLS(f.deviceConfig.Identity, f.policy.device.f.connector.ID)
	must(t, e)
	sc, e := f.policy.connector.trust.ConnectorServerTLS(f.connectorConfig.Identity, f.policy.device.trust)
	must(t, e)
	client, server := tls.Client(ra, cc), tls.Server(rb, sc)
	must(t, client.SetDeadline(time.Now().Add(8*time.Second)))
	must(t, server.SetDeadline(time.Now().Add(8*time.Second)))
	handshake := make(chan error, 1)
	go func() { handshake <- server.HandshakeContext(ctx) }()
	must(t, client.HandshakeContext(ctx))
	must(t, <-handshake)
	if !bytes.Equal(server.ConnectionState().PeerCertificates[0].Raw, f.policy.deviceLeaf) || !bytes.Equal(client.ConnectionState().PeerCertificates[0].Raw, f.policy.connectorLeaf) {
		t.Fatal("inner TLS authenticated a different peer")
	}
	request := bytes.Repeat([]byte("portico-secret-request-fixture-"), 10000)
	response := bytes.Repeat([]byte("portico-secret-response-fixture-"), 11000)
	serverDone := make(chan error, 1)
	go func() {
		got, e := io.ReadAll(server)
		if e == nil && !bytes.Equal(got, request) {
			e = io.ErrUnexpectedEOF
		}
		if e == nil {
			_, e = server.Write(response)
		}
		if e == nil {
			e = server.CloseWrite()
		}
		serverDone <- e
	}()
	_, e = client.Write(request)
	must(t, e)
	must(t, client.CloseWrite())
	got, e := io.ReadAll(client)
	must(t, e)
	if !bytes.Equal(got, response) {
		t.Fatal("half close discarded reverse traffic")
	}
	must(t, <-serverDone)
	for _, record := range []*recordedCarrier{ra, rb} {
		record.mu.Lock()
		plain := bytes.Contains(record.data, []byte("portico-secret-request-fixture-")) || bytes.Contains(record.data, []byte("portico-secret-response-fixture-"))
		n := len(record.data)
		record.mu.Unlock()
		if plain || n < 250000 {
			t.Fatal("relay bytes exposed plaintext or missed the actual traffic")
		}
	}
	must(t, a.Close())
	carrierStopped(t, a, b)
	carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 })
}

func TestCarrierWrongInnerConnectorFailsStandardNameCheck(t *testing.T) {
	f := newCarrierFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := f.pair(t, ctx)
	cc, e := f.policy.connector.trust.ConnectorClientTLS(f.deviceConfig.Identity, NewID())
	must(t, e)
	sc, e := f.policy.connector.trust.ConnectorServerTLS(f.connectorConfig.Identity, f.policy.device.trust)
	must(t, e)
	serverDone := make(chan error, 1)
	go func() { serverDone <- tls.Server(b, sc).HandshakeContext(ctx) }()
	if tls.Client(a, cc).HandshakeContext(ctx) == nil {
		t.Fatal("wrong paired connector was accepted")
	}
	must(t, a.Close())
	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal("rejected inner handshake leaked")
	}
	carrierStopped(t, a, b)
}

func rawCarrier(t *testing.T, c carrier.ClientConfig) pb.CarrierClient {
	t.Helper()
	root, e := x509.ParseCertificate(c.ServerRootDER)
	must(t, e)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	conn, e := grpc.NewClient("passthrough:///"+c.Endpoint[len("https://"):], grpc.WithNoProxy(), grpc.WithDisableRetry(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: pool, Certificates: []tls.Certificate{c.Identity}})))
	must(t, e)
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewCarrierClient(conn)
}

func carrierHello(t *testing.T, id string) *pb.Frame {
	t.Helper()
	nonce := make([]byte, 32)
	_, e := rand.Read(nonce)
	must(t, e)
	return &pb.Frame{Version: carrier.Version, Kind: pb.Kind_KIND_HELLO, ConnectorId: id, StreamId: nonce}
}

func carrierWatch(t *testing.T, ctx context.Context, api pb.CarrierClient, hello *pb.Frame) grpc.ServerStreamingClient[pb.Frame] {
	t.Helper()
	watch, e := api.Watch(ctx, hello)
	must(t, e)
	ready, e := watch.Recv()
	must(t, e)
	if ready.Kind != pb.Kind_KIND_READY || !bytes.Equal(ready.StreamId, hello.StreamId) {
		t.Fatal("watch was not bound to exact stream")
	}
	return watch
}

func TestCarrierMalformedHelloAndRoleConfusion(t *testing.T) {
	f := newCarrierFixture(t, func(c *carrier.Config) {
		c.HelloTimeout = 250 * time.Millisecond
		c.PairTimeout = 500 * time.Millisecond
	})
	api := rawCarrier(t, f.deviceConfig)
	for _, name := range []string{"version", "kind", "unknown", "data", "connector", "oversize", "empty", "no_hello", "bind_as_device", "short_id", "long_id"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			// Identity-like metadata must not change the certificate's role.
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-portico-profile", "connector", "x-portico-principal", f.policy.device.f.connector.ID))
			var stream grpc.BidiStreamingClient[pb.Frame, pb.Frame]
			var e error
			if name == "bind_as_device" {
				stream, e = api.Bind(ctx)
			} else {
				stream, e = api.Dial(ctx)
			}
			must(t, e)
			frame := carrierHello(t, f.policy.device.f.connector.ID)
			switch name {
			case "version":
				frame.Version++
			case "kind":
				frame.Kind = pb.Kind_KIND_DATA
			case "unknown":
				frame.ProtoReflect().SetUnknown([]byte{0x30, 1})
			case "data":
				frame.Data = []byte{1}
			case "connector":
				frame.ConnectorId = "127.0.0.1:22"
			case "oversize":
				frame.Data = make([]byte, carrier.MaxMessage+1)
			case "empty":
				frame = &pb.Frame{}
			case "short_id":
				frame.StreamId = frame.StreamId[:31]
			case "long_id":
				frame.StreamId = append(frame.StreamId, 0)
			}
			if name != "no_hello" {
				_ = stream.Send(frame)
			}
			if _, e = stream.Recv(); e == nil {
				t.Fatal("malformed stream was accepted")
			}
			if ctx.Err() != nil {
				t.Fatal("server did not reject within its own bound")
			}
			carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 && s.Waiting == 0 })
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e := f.connector.Bind(ctx, NewID()); e == nil {
		t.Fatal("connector bound another principal's slots")
	}
	if _, e := f.connector.Dial(ctx, f.policy.device.f.connector.ID); e == nil {
		t.Fatal("connector impersonated a device")
	}
}

func TestCarrierRejectsMalformedPairedData(t *testing.T) {
	f := newCarrierFixture(t, nil)
	api := rawCarrier(t, f.deviceConfig)
	for _, name := range []string{"unknown", "version", "kind", "connector", "empty", "oversize"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			bound := make(chan *carrier.Conn, 1)
			go func() { c, _ := f.connector.Bind(ctx, f.policy.device.f.connector.ID); bound <- c }()
			carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
			s, e := api.Dial(ctx)
			must(t, e)
			hello := carrierHello(t, f.policy.device.f.connector.ID)
			must(t, s.Send(hello))
			ready, e := s.Recv()
			must(t, e)
			if ready.Kind != pb.Kind_KIND_READY {
				t.Fatal("missing pairing response")
			}
			watch := carrierWatch(t, ctx, api, hello)
			b := <-bound
			if b == nil {
				t.Fatal("pairing failed")
			}
			defer b.Close()
			bad := &pb.Frame{Version: 1, Kind: pb.Kind_KIND_DATA, Data: []byte("bad")}
			switch name {
			case "unknown":
				bad.ProtoReflect().SetUnknown([]byte{0x30, 1})
			case "version":
				bad.Version++
			case "kind":
				bad.Kind = pb.Kind_KIND_READY
			case "connector":
				bad.ConnectorId = f.policy.device.f.connector.ID
			case "empty":
				bad.Data = nil
			case "oversize":
				bad.Data = make([]byte, carrier.MaxData+1)
			}
			_ = s.Send(bad)
			if _, e = s.Recv(); e == nil {
				t.Fatal("bad paired message survived")
			}
			if _, e = watch.Recv(); e == nil {
				t.Fatal("malformed stream retained its watch")
			}
			// An already closed pipe may reject SetReadDeadline; Read must still
			// return no bytes. The enclosing RPC context bounds a live pipe.
			_ = b.SetReadDeadline(time.Now().Add(time.Second))
			var buf [4]byte
			if n, _ := b.Read(buf[:]); n != 0 {
				t.Fatal("malformed frame reached peer")
			}
			carrierStopped(t, b)
			carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 })
		})
	}
}

func TestCarrierLiveRegistryRecheckedOnReusedConnection(t *testing.T) {
	f := newCarrierFixture(t, nil)
	a, b := f.pair(t, context.Background())
	must(t, a.Close())
	carrierStopped(t, a, b)
	carrierEventually(t, func() bool { return f.relay.Stats().Streams == 0 })
	s := f.policy.device.f.s
	must(t, s.Update(ctx, f.policy.device.f.actor, func(tx *Tx) error { return tx.Disable("device", f.policy.device.f.device.ID) }))
	admitted := f.admitted.Load()
	if _, e := f.device.Dial(ctx, f.policy.device.f.connector.ID); e == nil {
		t.Fatal("disabled device reused TLS connection")
	}
	if f.admitted.Load() != admitted {
		t.Fatal("revoked peer admitted before pairing")
	}
	// The previously established outer connection is still present: denial was
	// a live authority check, not a coincidental transport shutdown.
	if f.relay.Stats().Connections != 2 {
		t.Fatal("test did not exercise reused outer connections")
	}
}

func TestCarrierPerPrincipalQuotaSpansConnections(t *testing.T) {
	f := newCarrierFixture(t, func(c *carrier.Config) { c.MaxPeerStreams = 2; c.PairTimeout = 3 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		s, e := rawCarrier(t, f.connectorConfig).Bind(ctx)
		must(t, e)
		must(t, s.Send(carrierHello(t, f.policy.device.f.connector.ID)))
		want := i + 1
		carrierEventually(t, func() bool { return f.relay.Stats().Waiting == want })
	}
	s, e := rawCarrier(t, f.connectorConfig).Bind(ctx)
	must(t, e)
	_ = s.Send(carrierHello(t, f.policy.device.f.connector.ID))
	if _, e = s.Recv(); e == nil {
		t.Fatal("parallel connections bypassed peer quota")
	}
	if f.admitted.Load() != 2 || f.relay.Stats().Waiting != 2 {
		t.Fatal("over-quota request reached registry or displaced a slot")
	}
	cancel()
	carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 && s.Waiting == 0 })
}

func TestCarrierCancellationUnblocksSlowConsumer(t *testing.T) {
	for _, mode := range []string{"context", "client_close", "relay_close", "simultaneous_close"} {
		t.Run(mode, func(t *testing.T) {
			f := newCarrierFixture(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, b := f.pair(t, ctx)
			written := make(chan error, 1)
			started := make(chan struct{})
			go func() {
				buf := make([]byte, 64*1024)
				close(started)
				for i := 0; i < 512; i++ {
					if _, e := a.Write(buf); e != nil {
						written <- e
						return
					}
				}
				written <- nil
			}()
			<-started
			select {
			case e := <-written:
				t.Fatalf("32 MiB write did not backpressure: %v", e)
			case <-time.After(100 * time.Millisecond):
			}
			switch mode {
			case "context":
				cancel()
			case "client_close":
				must(t, f.device.Close())
			case "relay_close":
				f.relay.Close()
			case "simultaneous_close":
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func() { defer wg.Done(); _ = a.Close(); _ = b.Close() }()
				}
				wg.Wait()
			}
			select {
			case e := <-written:
				if e == nil {
					t.Fatal("blocked write survived cancellation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("blocked writer leaked")
			}
			carrierStopped(t, a, b)
			carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Waiting == 0 && s.Workers == 0 })
		})
	}
}

func TestCarrierIdleLifetimeAndAbandonedSlot(t *testing.T) {
	t.Run("idle_pair", func(t *testing.T) {
		f := newCarrierFixture(t, func(c *carrier.Config) { c.MaxLifetime = time.Second; c.PairTimeout = 500 * time.Millisecond })
		a, b := f.pair(t, context.Background())
		carrierStopped(t, a, b)
		carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 })
	})
	t.Run("abandoned_bind", func(t *testing.T) {
		f := newCarrierFixture(t, func(c *carrier.Config) { c.PairTimeout = 100 * time.Millisecond })
		if _, e := f.connector.Bind(context.Background(), f.policy.device.f.connector.ID); e == nil {
			t.Fatal("unpaired bind succeeded")
		}
		carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 && s.Waiting == 0 })
	})
}

func TestCarrierWatchIsBoundToExactCertificateAndStream(t *testing.T) {
	f := newCarrierFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api := rawCarrier(t, f.connectorConfig)
	hello := carrierHello(t, f.policy.device.f.connector.ID)
	s, e := api.Bind(ctx)
	must(t, e)
	must(t, s.Send(hello))
	carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
	// A public correlation ID is not authority, even with another admitted
	// identity and forged principal metadata on the same deployment.
	other := rawCarrier(t, f.deviceConfig)
	w, e := other.Watch(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-portico-principal", hello.ConnectorId)), hello)
	must(t, e)
	if _, e = w.Recv(); e == nil {
		t.Fatal("different leaf acquired a cancellation watch")
	}
	wrong := carrierHello(t, hello.ConnectorId)
	w, e = api.Watch(ctx, wrong)
	must(t, e)
	if _, e = w.Recv(); e == nil {
		t.Fatal("unknown stream ID acquired watch")
	}
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	watch := carrierWatch(t, watchCtx, api, hello)
	w, e = api.Watch(ctx, hello)
	must(t, e)
	if _, e = w.Recv(); e == nil {
		t.Fatal("duplicate watch accepted")
	}
	if f.relay.Stats().Waiting != 1 || f.relay.Stats().Watches != 1 {
		t.Fatal("rejected watch displaced legitimate stream")
	}
	watchCancel()
	if _, e = watch.Recv(); e == nil {
		t.Fatal("cancelled watch survived")
	}
	if _, e = s.Recv(); e == nil {
		t.Fatal("data stream survived watch loss")
	}
	carrierEventually(t, func() bool { s := f.relay.Stats(); return s.Streams == 0 && s.Workers == 0 && s.Endpoints == 0 })
}

func TestCarrierWatchRevocationAndMissingWatch(t *testing.T) {
	t.Run("revoked_before_watch", func(t *testing.T) {
		f := newCarrierFixture(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		api := rawCarrier(t, f.connectorConfig)
		hello := carrierHello(t, f.policy.device.f.connector.ID)
		s, e := api.Bind(ctx)
		must(t, e)
		must(t, s.Send(hello))
		carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
		must(t, f.policy.device.f.s.Update(ctx, f.policy.device.f.actor, func(tx *Tx) error { return tx.Disable("connector", hello.ConnectorId) }))
		w, e := api.Watch(ctx, hello)
		must(t, e)
		if _, e = w.Recv(); e == nil {
			t.Fatal("disabled connector acquired watch")
		}
		if _, e = s.Recv(); e == nil {
			t.Fatal("revoked watch retained data slot")
		}
	})
	t.Run("payload_before_watch", func(t *testing.T) {
		f := newCarrierFixture(t, func(c *carrier.Config) { c.HelloTimeout = 500 * time.Millisecond })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bound := make(chan *carrier.Conn, 1)
		go func() { c, _ := f.connector.Bind(ctx, f.policy.device.f.connector.ID); bound <- c }()
		carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
		api := rawCarrier(t, f.deviceConfig)
		s, e := api.Dial(ctx)
		must(t, e)
		must(t, s.Send(carrierHello(t, f.policy.device.f.connector.ID)))
		_, e = s.Recv()
		must(t, e)
		b := <-bound
		if b == nil {
			t.Fatal("connector pairing failed")
		}
		defer b.Close()
		must(t, s.Send(&pb.Frame{Version: 1, Kind: pb.Kind_KIND_DATA, Data: []byte("unwatched data")}))
		var buf [32]byte
		if n, _ := b.Read(buf[:]); n != 0 {
			t.Fatal("data forwarded before both watches existed")
		}
		carrierStopped(t, b)
	})
}

func TestCarrierClientQuotaAndRepeatedCloseReleasesCalls(t *testing.T) {
	f := newCarrierFixture(t, nil)
	limitedConfig := f.connectorConfig
	limitedConfig.MaxStreams = 1
	client, e := carrier.NewClient(limitedConfig)
	must(t, e)
	defer client.Close()
	for i := 0; i < 6; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ended := make(chan error, 1)
		go func() { _, e := client.Bind(ctx, f.policy.device.f.connector.ID); ended <- e }()
		carrierEventually(t, func() bool { return f.relay.Stats().Waiting == 1 })
		before := f.admitted.Load()
		if _, e := client.Bind(context.Background(), f.policy.device.f.connector.ID); e == nil {
			t.Fatal("local stream bound ignored")
		}
		if f.admitted.Load() != before {
			t.Fatal("locally over-quota call reached relay")
		}
		cancel()
		if e := <-ended; e == nil {
			t.Fatal("cancelled Bind succeeded")
		}
		carrierEventually(t, func() bool {
			return client.ActiveStreams() == 0 && f.relay.Stats().Streams == 0 && f.relay.Stats().Workers == 0
		})
	}
	must(t, client.Close())
	if _, e := client.Bind(context.Background(), f.policy.device.f.connector.ID); e == nil {
		t.Fatal("closed client opened a new call")
	}
}

func TestCarrierIndependentStreamsSurvivePeerStreamClose(t *testing.T) {
	f := newCarrierFixture(t, nil)
	a, b := f.pair(t, context.Background())
	c, d := f.pair(t, context.Background())
	must(t, a.Close())
	carrierStopped(t, a, b)
	write := make(chan error, 1)
	go func() { _, e := c.Write([]byte("second connection stays live")); write <- e }()
	must(t, d.SetReadDeadline(time.Now().Add(3*time.Second)))
	got := make([]byte, len("second connection stays live"))
	_, e := io.ReadFull(d, got)
	must(t, e)
	must(t, <-write)
	if string(got) != "second connection stays live" {
		t.Fatal("cross-stream payload corruption")
	}
	must(t, c.Close())
	carrierStopped(t, c, d)
}

func TestCarrierPinnedTransportAndClientConfiguration(t *testing.T) {
	f := newCarrierFixture(t, nil)
	for _, name := range []string{"http", "no_port", "path", "query", "fragment", "credentials", "bad_root", "nil_key", "empty_chain", "oversize_leaf", "streams", "open_timeout", "lifetime"} {
		t.Run(name, func(t *testing.T) {
			c := f.deviceConfig
			switch name {
			case "http":
				c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1)
			case "no_port":
				c.Endpoint = "https://localhost"
			case "path":
				c.Endpoint += "/api"
			case "query":
				c.Endpoint += "?token=fixture"
			case "fragment":
				c.Endpoint += "#fixture"
			case "credentials":
				c.Endpoint = strings.Replace(c.Endpoint, "https://", "https://fixture@", 1)
			case "bad_root":
				c.ServerRootDER = []byte{1, 2, 3}
			case "nil_key":
				c.Identity.PrivateKey = nil
			case "empty_chain":
				c.Identity.Certificate = nil
			case "oversize_leaf":
				c.Identity.Certificate = [][]byte{make([]byte, pki.MaxDER+1)}
			case "streams":
				c.MaxStreams = 0
			case "open_timeout":
				c.OpenTimeout = 0
			case "lifetime":
				c.MaxLifetime = time.Hour + time.Second
			}
			client, e := carrier.NewClient(c)
			if e == nil {
				_ = client.Close()
				t.Fatal("unsafe client configuration accepted")
			}
		})
	}
	for _, name := range []string{"wrong_pin", "wrong_name", "wrong_root", "foreign_identity"} {
		t.Run(name, func(t *testing.T) {
			c := f.deviceConfig
			root, key := testfixture.Root(t)
			switch name {
			case "wrong_pin":
				c.ServerSPKI = strings.Repeat("0", 64)
			case "wrong_name":
				c.Endpoint = strings.Replace(c.Endpoint, "localhost", "127.0.0.1", 1)
			case "wrong_root":
				c.ServerRootDER = root.Raw
			case "foreign_identity":
				c.Identity = testfixture.TLSIdentity(t, root, key, false)
			}
			client, e := carrier.NewClient(c)
			must(t, e)
			defer client.Close()
			if _, e = client.Dial(context.Background(), f.policy.device.f.connector.ID); e == nil {
				t.Fatal("TLS identity boundary accepted wrong trust")
			}
			if f.admitted.Load() != 0 {
				t.Fatal("failed TLS proof reached registry admission")
			}
		})
	}
}

func TestCarrierConnectionLimitAndGlobalStreamLimit(t *testing.T) {
	t.Run("tcp_connections", func(t *testing.T) {
		f := newCarrierFixture(t, func(c *carrier.Config) { c.MaxConnections = 2; c.HelloTimeout = 5 * time.Second })
		address := strings.TrimPrefix(f.deviceConfig.Endpoint, "https://")
		var pending []net.Conn
		for i := 0; i < 2; i++ {
			c, e := net.DialTimeout("tcp", address, time.Second)
			must(t, e)
			pending = append(pending, c)
			defer c.Close()
		}
		carrierEventually(t, func() bool { return f.relay.Stats().Connections == 2 })
		extra, e := net.DialTimeout("tcp", address, time.Second)
		must(t, e)
		defer extra.Close()
		must(t, extra.SetReadDeadline(time.Now().Add(time.Second)))
		var buf [1]byte
		_, e = extra.Read(buf[:])
		if e != io.EOF {
			t.Fatalf("excess TCP connection not closed: %v", e)
		}
		for _, c := range pending {
			must(t, c.Close())
		}
		carrierEventually(t, func() bool { return f.relay.Stats().Connections == 0 })
		a, b := f.pair(t, context.Background())
		must(t, a.Close())
		carrierStopped(t, a, b)
	})
	t.Run("logical_streams", func(t *testing.T) {
		f := newCarrierFixture(t, func(c *carrier.Config) { c.MaxStreams = 2; c.MaxPeerStreams = 2 })
		a, b := f.pair(t, context.Background())
		before := f.admitted.Load()
		if _, e := f.connector.Bind(context.Background(), f.policy.device.f.connector.ID); e == nil {
			t.Fatal("global stream quota bypassed")
		}
		if f.admitted.Load() != before {
			t.Fatal("globally over-quota stream reached admission")
		}
		must(t, a.Close())
		carrierStopped(t, a, b)
	})
}
