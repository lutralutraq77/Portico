package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "portico.local/portico/internal/carrierpb"
	"portico.local/portico/internal/pki"
)

type ClientConfig struct {
	Endpoint                 string
	ServerRootDER            []byte
	ServerSPKI               string
	Identity                 tls.Certificate
	MaxStreams               int
	OpenTimeout, MaxLifetime time.Duration
}
type Client struct {
	connection        *grpc.ClientConn
	api               pb.CarrierClient
	timeout, lifetime time.Duration
	calls             *callLifecycle
}

func NewClient(c ClientConfig) (*Client, error) {
	u, e := url.Parse(c.Endpoint)
	pin, pinError := hex.DecodeString(c.ServerSPKI)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.Path != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() == "" || pinError != nil || len(pin) != 32 || len(c.Identity.Certificate) == 0 || len(c.Identity.Certificate) > 3 || c.Identity.PrivateKey == nil || c.MaxStreams < 1 || c.MaxStreams > 64 || c.OpenTimeout <= 0 || c.OpenTimeout > 5*time.Second || c.MaxLifetime <= 0 || c.MaxLifetime > time.Hour || c.OpenTimeout > c.MaxLifetime || len(c.ServerRootDER) > pki.MaxDER {
		return nil, ErrRejected
	}
	root, e := x509.ParseCertificate(c.ServerRootDER)
	if e != nil || !root.IsCA {
		return nil, ErrRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	identity := tls.Certificate{PrivateKey: c.Identity.PrivateKey}
	for _, der := range c.Identity.Certificate {
		if len(der) == 0 || len(der) > pki.MaxDER {
			return nil, ErrRejected
		}
		identity.Certificate = append(identity.Certificate, bytes.Clone(der))
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), Certificates: []tls.Certificate{identity}, SessionTicketsDisabled: true}
	tc.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 3 || pki.Hash(s.PeerCertificates[0].RawSubjectPublicKeyInfo) != strings.ToLower(c.ServerSPKI) {
			return ErrRejected
		}
		return nil
	}
	calls := &callLifecycle{active: make(map[*callEnd]struct{}), limit: c.MaxStreams}
	connection, e := grpc.NewClient("passthrough:///"+u.Host, grpc.WithTransportCredentials(credentials.NewTLS(tc)), grpc.WithNoProxy(), grpc.WithDisableServiceConfig(), grpc.WithDisableRetry(), grpc.WithStaticStreamWindowSize(64*1024), grpc.WithStaticConnWindowSize(1024*1024), grpc.WithReadBufferSize(32*1024), grpc.WithWriteBufferSize(32*1024), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessage), grpc.MaxCallSendMsgSize(MaxMessage)), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: c.OpenTimeout}).DialContext(ctx, "tcp", u.Host)
	}))
	if e != nil {
		return nil, ErrRejected
	}
	return &Client{connection: connection, api: pb.NewCarrierClient(connection), timeout: c.OpenTimeout, lifetime: c.MaxLifetime, calls: calls}, nil
}
func (c *Client) Close() error { c.calls.stop(); return c.connection.Close() }
func (c *Client) ActiveStreams() int {
	c.calls.mu.Lock()
	defer c.calls.mu.Unlock()
	return len(c.calls.active)
}
func (c *Client) Dial(ctx context.Context, connector string) (*Conn, error) {
	return c.open(ctx, connector, false)
}
func (c *Client) Bind(ctx context.Context, connector string) (*Conn, error) {
	return c.open(ctx, connector, true)
}

func (c *Client) open(ctx context.Context, connector string, binding bool) (*Conn, error) {
	if !pki.ValidID(connector) {
		return nil, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, c.lifetime)
	end := &callEnd{cancel: cancel}
	if !c.calls.add(end) {
		cancel()
		return nil, ErrRejected
	}
	context.AfterFunc(ctx, func() { c.calls.remove(end) })
	timer := time.AfterFunc(c.timeout, cancel)
	success := false
	defer func() {
		timer.Stop()
		if !success {
			cancel()
		}
	}()
	var s grpc.BidiStreamingClient[pb.Frame, pb.Frame]
	var e error
	if binding {
		s, e = c.api.Bind(ctx)
	} else {
		s, e = c.api.Dial(ctx)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, ErrRejected
	}
	hello := &pb.Frame{Version: Version, Kind: pb.Kind_KIND_HELLO, ConnectorId: connector, StreamId: id}
	if e != nil || s.Send(hello) != nil {
		return nil, ErrRejected
	}
	ready, e := s.Recv()
	if e != nil || !valid(ready, pb.Kind_KIND_READY, connector) || !bytes.Equal(ready.StreamId, id) {
		return nil, ErrRejected
	}
	watch, e := c.api.Watch(ctx, hello)
	if e != nil {
		return nil, ErrRejected
	}
	ready, e = watch.Recv()
	if e != nil || !valid(ready, pb.Kind_KIND_READY, connector) || !bytes.Equal(ready.StreamId, id) || !timer.Stop() || ctx.Err() != nil {
		return nil, ErrRejected
	}
	success = true
	return byteConn(s, watch, cancel), nil
}

type callEnd struct{ cancel context.CancelFunc }
type callLifecycle struct {
	mu     sync.Mutex
	active map[*callEnd]struct{}
	limit  int
	closed bool
}

func (l *callLifecycle) add(c *callEnd) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || len(l.active) >= l.limit {
		return false
	}
	l.active[c] = struct{}{}
	return true
}
func (l *callLifecycle) remove(c *callEnd) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.active, c)
}
func (l *callLifecycle) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for c := range l.active {
		c.cancel()
	}
}

// Conn has standard net.Pipe deadline/backpressure behavior. Its bounded pumps
// cancel the gRPC call and close both pipe ends on any error or full close.
// TLS CloseWrite carries a TLS close-notify as ordinary data; this carrier does
// not reinterpret it as permission to discard traffic in the other direction.
type Conn struct {
	net.Conn
	pipe   net.Conn
	cancel context.CancelFunc
	once   sync.Once
	done   chan struct{}
	work   sync.WaitGroup
}

func byteConn(s stream, watch interface{ Recv() (*pb.Frame, error) }, cancel context.CancelFunc) *Conn {
	user, pipe := net.Pipe()
	c := &Conn{Conn: user, pipe: pipe, cancel: cancel, done: make(chan struct{})}
	c.work.Add(4)
	// Terminal status on DATA may be queued behind unread payload. This watch
	// receives no payload, has its own flow-control window, and is always read.
	// Any message/end after its initial READY is terminal and fails closed.
	go func() { defer c.work.Done(); _, _ = watch.Recv(); _ = c.Close() }()
	// RPC cancellation must also unblock a pump already waiting on net.Pipe,
	// not only one currently inside gRPC Send/Recv.
	go func() { defer c.work.Done(); <-s.Context().Done(); _ = c.Close() }()
	go func() {
		defer c.work.Done()
		defer c.Close()
		buffer := make([]byte, MaxData)
		for {
			n, e := pipe.Read(buffer)
			if n > 0 && s.Send(&pb.Frame{Version: Version, Kind: pb.Kind_KIND_DATA, Data: bytes.Clone(buffer[:n])}) != nil {
				return
			}
			if e != nil {
				return
			}
		}
	}()
	go func() {
		defer c.work.Done()
		defer c.Close()
		for {
			f, e := s.Recv()
			if e != nil || !valid(f, pb.Kind_KIND_DATA, "") {
				return
			}
			if _, e = pipe.Write(f.Data); e != nil {
				return
			}
		}
	}()
	go func() { c.work.Wait(); close(c.done) }()
	return c
}
func (c *Conn) Close() error {
	c.once.Do(func() { c.cancel(); _ = c.Conn.Close(); _ = c.pipe.Close() })
	return nil
}
func (c *Conn) Done() <-chan struct{} { return c.done }
