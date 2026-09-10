//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/testfixture"
)

func agentGuest(t *testing.T) {
	t.Helper()
	testfixture.RequireTerminalGuest(t)
	if os.Geteuid() != 0 {
		t.Fatal("requires disposable root filesystem")
	}
}

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/", "portico-agent-")
	testfixture.Must(t, err)
	t.Cleanup(func() { testfixture.Must(t, os.RemoveAll(dir)) })
	return filepath.Join(dir, "agent.sock")
}

func serveFixture(t *testing.T, b catalogBackend) (*server, string) {
	t.Helper()
	path := socketPath(t)
	l, err := localipc.Listen(path)
	testfixture.Must(t, err)
	s, err := newServer(b)
	testfixture.Must(t, err)
	done := make(chan error, 1)
	go func() { done <- s.grpc.Serve(&limitedListener{Listener: l, server: s}) }()
	t.Cleanup(func() {
		s.grpc.Stop()
		l.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("agent server did not join")
		}
		if s.connections.Load() != 0 || s.requests.Load() != 0 {
			t.Error("agent retained connections or requests")
		}
	})
	return s, path
}

func TestGuestAgentCatalogRPC(t *testing.T) {
	agentGuest(t)
	t.Run("fresh_catalog_and_real_command", func(t *testing.T) {
		var calls atomic.Int64
		_, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			v := resource()
			v.Revision = calls.Add(1)
			return []control.ResourceAccess{v}, nil
		}))
		for _, revision := range []int64{1, 2} {
			rows, err := Catalog(context.Background(), path)
			testfixture.Must(t, err)
			if len(rows) != 1 || rows[0].Revision != revision {
				t.Fatal("catalog reused stale state")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/portico", "agent", "catalog", "--socket", path).CombinedOutput()
		if err != nil {
			t.Fatalf("actual agent catalog: %v: %s", err, out)
		}
		var r struct {
			Version   int                      `json:"version"`
			Resources []control.ResourceAccess `json:"resources"`
		}
		testfixture.Must(t, json.Unmarshal(out, &r))
		if r.Version != 1 || len(r.Resources) != 1 || r.Resources[0].Revision != 3 || r.Resources[0].ID != resource().ID {
			t.Fatal("command changed exact inventory")
		}
	})
	t.Run("bad_requests_never_reach_backend", func(t *testing.T) {
		var calls atomic.Int64
		_, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			calls.Add(1)
			return []control.ResourceAccess{}, nil
		}))
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		api := pb.NewAgentClient(c)
		future := &pb.CatalogRequest{Version: Version}
		future.ProtoReflect().SetUnknown([]byte{0x10, 1})
		for _, r := range []*pb.CatalogRequest{{}, {Version: 2}, future} {
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
			_, err := api.Catalog(ctx, r)
			cancel()
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("bad request status: %v", err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		err = c.Invoke(ctx, "/portico.agent.v1.Agent/Unimplemented", &pb.CatalogRequest{Version: Version}, &pb.CatalogResponse{})
		if status.Code(err) != codes.PermissionDenied || calls.Load() != 0 {
			t.Fatal("unknown operation reached backend or was accepted")
		}
	})
	t.Run("backend_failure_is_redacted", func(t *testing.T) {
		_, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			return nil, errors.New("synthetic-sensitive-backend-detail")
		}))
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		_, err = pb.NewAgentClient(c).Catalog(ctx, &pb.CatalogRequest{Version: Version})
		if status.Code(err) != codes.PermissionDenied || strings.Contains(err.Error(), "synthetic-sensitive") {
			t.Fatal("backend failure was not redacted")
		}
	})
	t.Run("oversized_message_rejected_before_backend", func(t *testing.T) {
		var calls atomic.Int64
		_, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			calls.Add(1)
			return []control.ResourceAccess{}, nil
		}))
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		r := &pb.CatalogRequest{Version: Version}
		unknown := protowire.AppendTag(nil, 2, protowire.BytesType)
		unknown = protowire.AppendBytes(unknown, make([]byte, MaxMessage))
		r.ProtoReflect().SetUnknown(unknown)
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		_, err = pb.NewAgentClient(c).Catalog(ctx, r, grpc.MaxCallSendMsgSize(MaxMessage*2))
		if status.Code(err) != codes.ResourceExhausted || calls.Load() != 0 {
			t.Fatalf("oversized request reached backend or wrong status: %v", err)
		}
	})
	t.Run("oversized_response_headers_rejected", func(t *testing.T) {
		_, path := serveFixture(t, backendFunc(func(ctx context.Context) ([]control.ResourceAccess, error) {
			if err := grpc.SetHeader(ctx, metadata.Pairs("fixture-header", strings.Repeat("h", 8193))); err != nil {
				return nil, err
			}
			return []control.ResourceAccess{}, nil
		}))
		if rows, err := Catalog(context.Background(), path); rows != nil || err == nil {
			t.Fatal("oversized response headers accepted")
		}
	})
	t.Run("cancellation_joins_active_backend", func(t *testing.T) {
		started := make(chan struct{})
		finished := make(chan struct{})
		s, path := serveFixture(t, backendFunc(func(ctx context.Context) ([]control.ResourceAccess, error) {
			close(started)
			<-ctx.Done()
			close(finished)
			return nil, ctx.Err()
		}))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := Catalog(ctx, path); done <- err }()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("backend did not start")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled call succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("client cancellation blocked")
		}
		s.grpc.Stop()
		select {
		case <-finished:
		default:
			t.Fatal("backend not joined on stop")
		}
	})
	t.Run("expired_window_blocks_new_backend_work", func(t *testing.T) {
		var calls atomic.Int64
		s, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			calls.Add(1)
			return []control.ResourceAccess{}, nil
		}))
		s.window.mu.Lock()
		s.window.closed = true
		s.window.mu.Unlock()
		if rows, err := Catalog(context.Background(), path); rows != nil || err == nil || calls.Load() != 0 {
			t.Fatal("closed unlock window admitted work")
		}
	})
	t.Run("raw_connections_cannot_exceed_cap", func(t *testing.T) {
		s, path := serveFixture(t, backendFunc(func(context.Context) ([]control.ResourceAccess, error) {
			t.Fatal("raw handshake reached backend")
			return nil, nil
		}))
		var peers []net.Conn
		defer func() {
			for _, c := range peers {
				c.Close()
			}
		}()
		for range maxConnections {
			c, err := localipc.Dial(context.Background(), path)
			testfixture.Must(t, err)
			peers = append(peers, c)
		}
		deadline := time.Now().Add(time.Second)
		for s.connections.Load() != maxConnections && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if s.connections.Load() != maxConnections {
			t.Fatal("fixture did not fill admission cap")
		}
		c, err := localipc.Dial(context.Background(), path)
		if err == nil {
			defer c.Close()
			testfixture.Must(t, c.SetReadDeadline(time.Now().Add(time.Second)))
			var b [1]byte
			_, err = c.Read(b[:])
			if err == nil {
				t.Fatal("excess connection received transport data")
			}
		}
		if s.connections.Load() != maxConnections {
			t.Fatal("excess connection changed admitted count")
		}
		s.grpc.Stop()
		if s.connections.Load() != 0 {
			t.Fatal("stop retained unauthenticated handshakes")
		}
	})
}

func TestGuestAgentRunShutdown(t *testing.T) {
	agentGuest(t)
	path := socketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, path, backendFunc(func(context.Context) ([]control.ResourceAccess, error) { return []control.ResourceAccess{}, nil }))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not create socket")
		}
		time.Sleep(time.Millisecond)
	}
	_, err := Catalog(context.Background(), path)
	testfixture.Must(t, err)
	cancel()
	select {
	case err := <-done:
		testfixture.Must(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not join on shutdown")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("agent left socket after orderly shutdown")
	}
}
