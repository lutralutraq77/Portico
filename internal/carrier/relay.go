// Package carrier transports opaque inner TLS over bounded gRPC streams.
// Admission and stream pairing never authorize a workload destination.
package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	pb "portico.local/portico/internal/carrierpb"
	"portico.local/portico/internal/pki"
)

const Version = 1
const MaxData = 32 * 1024
const MaxMessage = MaxData + 256

var ErrRejected = errors.New("carrier rejected")

type Config struct {
	ServerIdentity      tls.Certificate
	Devices, Connectors *pki.Trust
	// Admit must check the live registry on every admitted RPC. The relay has already
	// verified the TLS proof, typed profile and issuer pin; headers are unused.
	Admit                                      func(context.Context, pki.Credential, []byte) error
	MaxConnections, MaxStreams, MaxPeerStreams int
	HelloTimeout, PairTimeout, MaxLifetime     time.Duration
}

type Relay struct {
	pb.UnimplementedCarrierServer
	config      Config
	server      *grpc.Server
	mu          sync.Mutex
	streams     int
	peers       map[string]int
	slots       map[string][]*slot
	endpoints   map[string]*endpoint
	connections atomic.Int64
	workers     atomic.Int64
	work        sync.WaitGroup
}

type stream interface {
	Context() context.Context
	Recv() (*pb.Frame, error)
	Send(*pb.Frame) error
}
type received struct {
	frame *pb.Frame
	err   error
}
type slot struct {
	stream   stream
	frames   <-chan received
	ctx      context.Context
	matched  chan *pair
	endpoint *endpoint
}
type endpoint struct {
	leaf, connector string
	id              []byte
	ctx             context.Context
	cancel          context.CancelFunc
	watching        bool // protected by Relay.mu
	watched         chan struct{}
}
type pair struct {
	done chan struct{}
	once sync.Once
}

func (p *pair) close() { p.once.Do(func() { close(p.done) }) }

func New(c Config) (*Relay, error) {
	if c.Devices == nil || c.Connectors == nil || c.Devices.Profile() != pki.Device || c.Connectors.Profile() != pki.Connector || c.Devices.DeploymentID() != c.Connectors.DeploymentID() || c.Devices.IssuerFingerprint() == c.Connectors.IssuerFingerprint() || c.Admit == nil || len(c.ServerIdentity.Certificate) == 0 || c.ServerIdentity.PrivateKey == nil || c.MaxConnections < 1 || c.MaxConnections > 128 || c.MaxStreams < 2 || c.MaxStreams > 1024 || c.MaxPeerStreams < 1 || c.MaxPeerStreams > 64 || c.MaxPeerStreams > c.MaxStreams || c.HelloTimeout <= 0 || c.HelloTimeout > 5*time.Second || c.PairTimeout <= 0 || c.PairTimeout > 30*time.Second || c.MaxLifetime <= 0 || c.MaxLifetime > time.Hour || c.PairTimeout > c.MaxLifetime {
		return nil, ErrRejected
	}
	r := &Relay{config: c, peers: map[string]int{}, slots: map[string][]*slot{}, endpoints: map[string]*endpoint{}}
	identity := tls.Certificate{PrivateKey: c.ServerIdentity.PrivateKey}
	for _, der := range c.ServerIdentity.Certificate {
		identity.Certificate = append(identity.Certificate, bytes.Clone(der))
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true}
	tc.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 3 {
			return ErrRejected
		}
		if _, e := c.Devices.VerifyPeer(s.PeerCertificates[0].Raw, time.Now()); e == nil {
			return nil
		}
		if _, e := c.Connectors.VerifyPeer(s.PeerCertificates[0].Raw, time.Now()); e == nil {
			return nil
		}
		return ErrRejected
	}
	r.server = grpc.NewServer(grpc.Creds(credentials.NewTLS(tc)), grpc.MaxConcurrentStreams(uint32(2*c.MaxPeerStreams)), grpc.MaxRecvMsgSize(MaxMessage), grpc.MaxSendMsgSize(MaxMessage), grpc.StaticStreamWindowSize(64*1024), grpc.StaticConnWindowSize(1024*1024), grpc.ReadBufferSize(32*1024), grpc.WriteBufferSize(32*1024), grpc.MaxHeaderListSize(8192), grpc.ConnectionTimeout(c.HelloTimeout), grpc.WaitForHandlers(true), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: time.Minute, MaxConnectionAge: time.Hour, MaxConnectionAgeGrace: 5 * time.Second, Time: time.Minute, Timeout: 10 * time.Second}), grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error { return reject() }))
	pb.RegisterCarrierServer(r.server, r)
	return r, nil
}

func reject() error { return status.Error(codes.PermissionDenied, "carrier rejected") }
func valid(f *pb.Frame, kind pb.Kind, connector string) bool {
	if f == nil || (kind != pb.Kind_KIND_HELLO && kind != pb.Kind_KIND_READY && kind != pb.Kind_KIND_DATA) || f.Version != Version || f.Kind != kind || f.ConnectorId != connector || len(f.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	if kind == pb.Kind_KIND_DATA {
		return len(f.Data) > 0 && len(f.Data) <= MaxData && connector == "" && len(f.StreamId) == 0
	}
	return pki.ValidID(connector) && len(f.Data) == 0 && len(f.StreamId) == 32
}

func (r *Relay) identity(ctx context.Context, profile pki.Profile) (pki.Credential, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return pki.Credential{}, ErrRejected
	}
	auth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !auth.State.HandshakeComplete || auth.State.Version != tls.VersionTLS13 || len(auth.State.PeerCertificates) == 0 || len(auth.State.PeerCertificates) > 3 {
		return pki.Credential{}, ErrRejected
	}
	trust := r.config.Devices
	if profile == pki.Connector {
		trust = r.config.Connectors
	}
	der := auth.State.PeerCertificates[0].Raw
	v, e := trust.VerifyPeer(der, time.Now())
	if e != nil {
		return v, ErrRejected
	}
	return v, nil
}

func (r *Relay) acquire(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams >= r.config.MaxStreams || r.peers[id] >= r.config.MaxPeerStreams {
		return false
	}
	r.streams++
	r.peers[id]++
	return true
}
func (r *Relay) release(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams--
	r.peers[id]--
	if r.peers[id] == 0 {
		delete(r.peers, id)
	}
}
func (r *Relay) worker(f func()) {
	r.work.Add(1)
	r.workers.Add(1)
	go func() { defer r.work.Done(); defer r.workers.Add(-1); f() }()
}
func (r *Relay) receive(ctx context.Context, s stream) <-chan received {
	ch := make(chan received)
	r.worker(func() {
		defer close(ch)
		for {
			f, e := s.Recv()
			select {
			case ch <- received{f, e}:
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	})
	return ch
}

func (r *Relay) hello(ctx context.Context, ch <-chan received) (*pb.Frame, error) {
	timer := time.NewTimer(r.config.HelloTimeout)
	defer timer.Stop()
	select {
	case v := <-ch:
		if v.err != nil || v.frame == nil || !valid(v.frame, pb.Kind_KIND_HELLO, v.frame.ConnectorId) {
			return nil, ErrRejected
		}
		return v.frame, nil
	case <-ctx.Done():
		return nil, ErrRejected
	case <-timer.C:
		return nil, ErrRejected
	}
}

func (r *Relay) serve(s stream, binding bool) error {
	role := pki.Device
	if binding {
		role = pki.Connector
	}
	v, e := r.identity(s.Context(), role)
	if e != nil {
		return reject()
	}
	if !r.acquire(v.PrincipalID) {
		return reject()
	}
	defer r.release(v.PrincipalID)
	check, stopCheck := context.WithTimeout(s.Context(), r.config.HelloTimeout)
	remote, _ := peer.FromContext(s.Context())
	der := remote.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0].Raw
	e = r.config.Admit(check, v, bytes.Clone(der))
	if check.Err() != nil {
		e = ErrRejected
	}
	stopCheck()
	if e != nil {
		return reject()
	}
	deadline := time.Now().Add(r.config.MaxLifetime)
	if v.NotAfter.Before(deadline) {
		deadline = v.NotAfter
	}
	ctx, cancel := context.WithDeadline(s.Context(), deadline)
	defer cancel()
	frames := r.receive(ctx, s)
	hello, e := r.hello(ctx, frames)
	if e != nil {
		return reject()
	}
	local := &endpoint{leaf: v.LeafSHA256, connector: hello.ConnectorId, id: bytes.Clone(hello.StreamId), ctx: ctx, cancel: cancel, watched: make(chan struct{})}
	r.mu.Lock()
	_, exists := r.endpoints[string(local.id)]
	if !exists {
		r.endpoints[string(local.id)] = local
	}
	r.mu.Unlock()
	if exists {
		return reject()
	}
	defer func() { r.mu.Lock(); delete(r.endpoints, string(local.id)); r.mu.Unlock() }()
	if binding {
		if hello.ConnectorId != v.PrincipalID {
			return reject()
		}
		slot := &slot{stream: s, frames: frames, ctx: ctx, matched: make(chan *pair, 1), endpoint: local}
		r.mu.Lock()
		r.slots[v.PrincipalID] = append(r.slots[v.PrincipalID], slot)
		r.mu.Unlock()
		defer r.remove(v.PrincipalID, slot)
		timer := time.NewTimer(r.config.PairTimeout)
		defer timer.Stop()
		select {
		case p := <-slot.matched:
			defer p.close()
			select {
			case <-p.done:
			case <-ctx.Done():
			}
		case <-ctx.Done():
		case <-timer.C:
		}
		return reject()
	}
	slot := r.take(hello.ConnectorId)
	if slot == nil {
		return reject()
	}
	p := &pair{done: make(chan struct{})}
	defer p.close()
	slot.matched <- p
	// This handler is the only writer of both READY frames. Once they are
	// sent, each direction has exactly one writer in forward.
	ready := func(id []byte) *pb.Frame {
		return &pb.Frame{Version: Version, Kind: pb.Kind_KIND_READY, ConnectorId: hello.ConnectorId, StreamId: id}
	}
	if r.sendReady(ctx, slot.ctx, slot.stream, ready(slot.endpoint.id)) != nil || r.sendReady(ctx, slot.ctx, s, ready(local.id)) != nil {
		return reject()
	}
	// Both independently authenticated watches must be ready before payload
	// forwarding. There is no fallback to an unobservable, blocked DATA stream.
	timer := time.NewTimer(r.config.HelloTimeout)
	defer timer.Stop()
	for _, ep := range []*endpoint{local, slot.endpoint} {
		select {
		case <-ep.watched:
		case <-timer.C:
			return reject()
		case <-ctx.Done():
			return reject()
		case <-slot.ctx.Done():
			return reject()
		}
	}
	r.forward(ctx, p, frames, slot.stream)
	r.forward(slot.ctx, p, slot.frames, s)
	select {
	case <-p.done:
	case <-ctx.Done():
	case <-slot.ctx.Done():
	}
	return reject()
}

func (r *Relay) sendReady(ctx, other context.Context, s interface{ Send(*pb.Frame) error }, f *pb.Frame) error {
	done := make(chan error, 1)
	r.worker(func() { done <- s.Send(f) })
	select {
	case e := <-done:
		return e
	case <-ctx.Done():
		return ErrRejected
	case <-other.Done():
		return ErrRejected
	}
}

func (r *Relay) forward(ctx context.Context, p *pair, ch <-chan received, to stream) {
	r.worker(func() {
		defer p.close()
		for {
			select {
			case v, ok := <-ch:
				if !ok || v.err != nil || !valid(v.frame, pb.Kind_KIND_DATA, "") || to.Send(v.frame) != nil {
					return
				}
			case <-ctx.Done():
				return
			case <-p.done:
				return
			}
		}
	})
}

func (r *Relay) remove(id string, s *slot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.slots[id]
	for i, v := range list {
		if v == s {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(r.slots, id)
	} else {
		r.slots[id] = list
	}
}
func (r *Relay) take(id string) *slot {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.slots[id]
	var result *slot
	for len(list) > 0 {
		candidate := list[0]
		list = list[1:]
		if candidate.ctx.Err() == nil {
			result = candidate
			break
		}
	}
	if len(list) == 0 {
		delete(r.slots, id)
	} else {
		r.slots[id] = list
	}
	return result
}

func (r *Relay) Dial(s grpc.BidiStreamingServer[pb.Frame, pb.Frame]) error { return r.serve(s, false) }
func (r *Relay) Bind(s grpc.BidiStreamingServer[pb.Frame, pb.Frame]) error { return r.serve(s, true) }

func (r *Relay) Watch(req *pb.Frame, s grpc.ServerStreamingServer[pb.Frame]) error {
	if req == nil || !valid(req, pb.Kind_KIND_HELLO, req.ConnectorId) {
		return reject()
	}
	v, e := r.identity(s.Context(), pki.Device)
	if e != nil {
		v, e = r.identity(s.Context(), pki.Connector)
	}
	if e != nil {
		return reject()
	}
	r.mu.Lock()
	ep := r.endpoints[string(req.StreamId)]
	accepted := ep != nil && ep.leaf == v.LeafSHA256 && ep.connector == req.ConnectorId && !ep.watching && ep.ctx.Err() == nil
	if accepted {
		ep.watching = true
	}
	r.mu.Unlock()
	if !accepted {
		return reject()
	}
	defer ep.cancel()
	watch, cancel := context.WithTimeout(s.Context(), r.config.HelloTimeout)
	remote, _ := peer.FromContext(s.Context())
	der := remote.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0].Raw
	e = r.config.Admit(watch, v, bytes.Clone(der))
	if e != nil || watch.Err() != nil {
		cancel()
		return reject()
	}
	e = r.sendReady(watch, ep.ctx, s, &pb.Frame{Version: Version, Kind: pb.Kind_KIND_READY, ConnectorId: ep.connector, StreamId: ep.id})
	cancel()
	if e != nil {
		return reject()
	}
	close(ep.watched)
	select {
	case <-s.Context().Done():
	case <-ep.ctx.Done():
	}
	return reject()
}

// Serve remains restricted to an explicitly supplied loopback listener during
// the prototype. Deployment exposure requires the independent network profile.
func (r *Relay) Serve(l net.Listener) error {
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return ErrRejected
	}
	return r.server.Serve(&limitedListener{Listener: l, relay: r})
}
func (r *Relay) Close() { r.server.Stop(); r.work.Wait() }

type Stats struct {
	Streams, Waiting     int
	Endpoints, Watches   int
	Connections, Workers int64
}

func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := Stats{Streams: r.streams, Connections: r.connections.Load(), Workers: r.workers.Load()}
	stats.Endpoints = len(r.endpoints)
	for _, ep := range r.endpoints {
		if ep.watching {
			stats.Watches++
		}
	}
	for _, list := range r.slots {
		stats.Waiting += len(list)
	}
	return stats
}

type limitedListener struct {
	net.Listener
	relay *Relay
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if l.relay.connections.Add(1) > int64(l.relay.config.MaxConnections) {
			l.relay.connections.Add(-1)
			_ = c.Close()
			continue
		}
		return &limitedConn{Conn: c, relay: l.relay}, nil
	}
}

type limitedConn struct {
	net.Conn
	relay *Relay
	once  sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(func() { c.relay.connections.Add(-1) })
	return c.Conn.Close()
}
