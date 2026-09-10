package agent

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/localipc"
)

type catalogBackend interface {
	Catalog(context.Context) ([]control.ResourceAccess, error)
}

// Run owns the private socket for one bounded unlock window, including suspend.
// The CLI loads only an explicitly unlocked encrypted identity before calling
// it and exits afterward. Every request fetches a fresh catalog. This is not a
// guarantee that the Go runtime erases the supplied key's memory on return.
func Run(ctx context.Context, path string, config *client.Configuration) error {
	if config == nil {
		return ErrRejected
	}
	return run(ctx, path, config)
}

func run(ctx context.Context, path string, backend catalogBackend) (result error) {
	if ctx == nil || ctx.Err() != nil || backend == nil {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, unlockLifetime)
	defer cancel()
	l, err := localipc.Listen(path)
	if err != nil {
		return ErrRejected
	}
	defer func() {
		if l.Close() != nil {
			result = ErrRejected
		}
	}()
	s, err := newServer(backend)
	if err != nil {
		return ErrRejected
	}
	defer s.grpc.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	done := make(chan error, 1)
	go func() { done <- s.grpc.Serve(&limitedListener{Listener: l, server: s}) }()
	for {
		select {
		case <-ctx.Done():
			s.grpc.Stop()
			<-done
			return nil
		case <-done:
			return ErrRejected
		case <-tick.C:
			if !s.window.valid() {
				s.grpc.Stop()
				<-done
				return nil
			}
		}
	}
}

type server struct {
	pb.UnimplementedAgentServer
	backend     catalogBackend
	grpc        *grpc.Server
	connections atomic.Int64
	requests    atomic.Int64
	window      *window
}

func newServer(backend catalogBackend) (*server, error) {
	w, err := newWindow()
	if err != nil {
		return nil, err
	}
	s := &server{backend: backend, window: w}
	// The credentials adapter recognizes the Unix transport. UID verification
	// is performed by localipc.Listen before gRPC receives a connection.
	s.grpc = grpc.NewServer(grpc.Creds(local.NewCredentials()), grpc.MaxConcurrentStreams(1), grpc.MaxRecvMsgSize(MaxMessage), grpc.MaxSendMsgSize(MaxMessage), grpc.StaticStreamWindowSize(64*1024), grpc.StaticConnWindowSize(64*1024), grpc.MaxHeaderListSize(8192), grpc.ReadBufferSize(4096), grpc.WriteBufferSize(4096), grpc.ConnectionTimeout(operationTimeout), grpc.WaitForHandlers(true), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 30 * time.Second, MaxConnectionAge: unlockLifetime, MaxConnectionAgeGrace: operationTimeout}), grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error { return rejected() }))
	pb.RegisterAgentServer(s.grpc, s)
	return s, nil
}

func rejected() error { return status.Error(codes.PermissionDenied, "local agent operation rejected") }

func (s *server) Catalog(ctx context.Context, r *pb.CatalogRequest) (*pb.CatalogResponse, error) {
	if !validRequest(r) || ctx == nil || ctx.Err() != nil || !s.window.valid() {
		return nil, rejected()
	}
	if s.requests.Add(1) > maxConnections {
		s.requests.Add(-1)
		return nil, rejected()
	}
	defer s.requests.Add(-1)
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	resources, err := s.backend.Catalog(ctx)
	if err != nil || ctx.Err() != nil || !s.window.valid() {
		return nil, rejected()
	}
	response, err := encodeCatalog(resources)
	if err != nil {
		return nil, rejected()
	}
	return response, nil
}

type limitedListener struct {
	net.Listener
	server *server
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.server.connections.Add(1) > maxConnections {
			l.server.connections.Add(-1)
			_ = c.Close()
			continue
		}
		return &countedConn{Conn: c, server: l.server}, nil
	}
}

type countedConn struct {
	net.Conn
	server   *server
	once     sync.Once
	closeErr error
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.server.connections.Add(-1) })
	return c.closeErr
}
