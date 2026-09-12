//go:build linux

package agent

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/testfixture"
)

var daemonPassphrase = []byte("synthetic-daemon-unlock-passphrase")

func daemonFixture(t *testing.T, b resourceBackend) (*manager, *server, string, *atomic.Int64) {
	t.Helper()
	m, clock, _ := sessionFixture(t, func(_ context.Context, passphrase []byte) (resourceBackend, error) {
		if !bytes.Equal(passphrase, daemonPassphrase) {
			return nil, ErrRejected
		}
		return b, nil
	})
	s, path := serveFixture(t, m)
	return m, s, path, clock
}

func TestGuestAgentDaemonRPC(t *testing.T) {
	agentGuest(t)
	t.Run("locked_unlock_status_lock_and_actual_commands", func(t *testing.T) {
		_, _, path, _ := daemonFixture(t, streamFunc(echoStream))
		state, err := Status(context.Background(), path)
		testfixture.Must(t, err)
		if state != "locked" {
			t.Fatal("daemon did not start locked")
		}
		if _, err := Catalog(context.Background(), path); err == nil {
			t.Fatal("locked daemon served catalog")
		}
		_, _, done, _ := tunnelPipes(t, path)
		expectTunnelEnd(t, done, false)
		testfixture.Must(t, Unlock(context.Background(), path, daemonPassphrase))
		state, err = Status(context.Background(), path)
		testfixture.Must(t, err)
		if state != "unlocked" {
			t.Fatal("unlock did not publish state")
		}
		rows, err := Catalog(context.Background(), path)
		testfixture.Must(t, err)
		if len(rows) != 1 || rows[0] != resource() {
			t.Fatal("unlocked inventory changed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/portico", "agent", "status", "--socket", path).CombinedOutput()
		if err != nil || string(out) != "{\"version\":1,\"state\":\"unlocked\"}\n" {
			t.Fatalf("actual status: %v %q", err, out)
		}
		out, err = exec.CommandContext(ctx, "/portico", "agent", "lock", "--socket", path).CombinedOutput()
		if err != nil || string(out) != "Local agent locked.\n" {
			t.Fatalf("actual lock: %v %q", err, out)
		}
		if _, err := Catalog(context.Background(), path); err == nil {
			t.Fatal("locked daemon reused key")
		}
	})
	t.Run("invalid_unlock_never_reaches_loader", func(t *testing.T) {
		var loads atomic.Int64
		m, _, _ := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) { loads.Add(1); return sessionBackend{}, nil })
		_, path := serveFixture(t, m)
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		future := &pb.UnlockRequest{Version: Version, Passphrase: daemonPassphrase}
		future.ProtoReflect().SetUnknown([]byte{0x18, 1})
		for _, r := range []*pb.UnlockRequest{{}, {Version: 2, Passphrase: daemonPassphrase}, future, {Version: Version, Passphrase: []byte("short")}, {Version: Version, Passphrase: bytes.Repeat([]byte{'x'}, 1025)}, {Version: Version, Passphrase: bytes.Repeat([]byte{0xff}, 20)}} {
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
			_, err := pb.NewAgentClient(c).Unlock(ctx, r)
			cancel()
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("malformed unlock: %v", err)
			}
		}
		if loads.Load() != 0 {
			t.Fatal("invalid unlock started KDF")
		}
	})
	t.Run("invalid_control_preserves_unlocked_session", func(t *testing.T) {
		_, _, path, _ := daemonFixture(t, streamFunc(echoStream))
		testfixture.Must(t, Unlock(context.Background(), path, daemonPassphrase))
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		future := &pb.StateRequest{Version: Version}
		future.ProtoReflect().SetUnknown([]byte{0x10, 1})
		for _, r := range []*pb.StateRequest{{}, {Version: 2}, future} {
			ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
			_, err = pb.NewAgentClient(c).Status(ctx, r)
			if status.Code(err) != codes.PermissionDenied {
				cancel()
				t.Fatal("invalid status accepted")
			}
			_, err = pb.NewAgentClient(c).Lock(ctx, r)
			cancel()
			if status.Code(err) != codes.PermissionDenied {
				t.Fatal("invalid lock accepted")
			}
		}
		state, err := Status(context.Background(), path)
		testfixture.Must(t, err)
		if state != "unlocked" {
			t.Fatal("invalid control changed active identity")
		}
	})
	t.Run("six_active_streams_leave_control_capacity", func(t *testing.T) {
		var active atomic.Int64
		_, s, path, _ := daemonFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, _ client.Output, ready func() error) error {
			active.Add(1)
			defer active.Add(-1)
			if ready() != nil {
				return ErrRejected
			}
			<-ctx.Done()
			return ctx.Err()
		}))
		testfixture.Must(t, Unlock(context.Background(), path, daemonPassphrase))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var clients []*grpc.ClientConn
		var streams []grpc.BidiStreamingClient[pb.TunnelFrame, pb.TunnelFrame]
		defer func() {
			for _, c := range clients {
				c.Close()
			}
		}()
		for range maxConnections - 2 {
			c, err := newClient(path)
			testfixture.Must(t, err)
			clients = append(clients, c)
			stream, err := pb.NewAgentClient(c).Connect(ctx)
			testfixture.Must(t, err)
			open := frame(pb.TunnelFrame_OPEN)
			open.ResourceId, open.Revision = resource().ID, resource().Revision
			testfixture.Must(t, stream.Send(open))
			r, err := stream.Recv()
			testfixture.Must(t, err)
			if !validFrame(r, pb.TunnelFrame_READY) {
				t.Fatal("missing READY")
			}
			streams = append(streams, stream)
		}
		if active.Load() != maxConnections-2 {
			t.Fatal("stream cap not filled")
		}
		_, _, excess, _ := tunnelPipes(t, path)
		expectTunnelEnd(t, excess, false)
		state, err := Status(ctx, path)
		testfixture.Must(t, err)
		if state != "unlocked" {
			t.Fatal("control blocked by streams")
		}
		testfixture.Must(t, Lock(ctx, path))
		for _, stream := range streams {
			r, err := stream.Recv()
			if err == nil && validFrame(r, pb.TunnelFrame_FIN) {
				_, err = stream.Recv()
			}
			if status.Code(err) != codes.PermissionDenied {
				t.Fatal("locked stream retained access")
			}
		}
		s.stop()
		if active.Load() != 0 || s.requests.Load() != 0 || s.streams.Load() != 0 {
			t.Fatal("locked streams not joined")
		}
	})
	t.Run("boot_clock_expiry_cancels_live_stream", func(t *testing.T) {
		started := make(chan struct{})
		m, _, path, clock := daemonFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, _ client.Output, ready func() error) error {
			if ready() != nil {
				return ErrRejected
			}
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}))
		testfixture.Must(t, Unlock(context.Background(), path, daemonPassphrase))
		_, _, done, _ := tunnelPipes(t, path)
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("stream did not start")
		}
		clock.Add(int64(unlockLifetime))
		if !m.healthy() {
			t.Fatal("ordinary expiry broke daemon")
		}
		expectTunnelEnd(t, done, false)
		testfixture.Must(t, Lock(context.Background(), path))
		state, err := Status(context.Background(), path)
		testfixture.Must(t, err)
		if state != "locked" {
			t.Fatal("expired state reopened")
		}
	})
}

func TestGuestAgentDaemonRestartsLocked(t *testing.T) {
	agentGuest(t)
	path := socketPath(t)
	configuration := filepath.Join(filepath.Dir(path), "client.json")
	// Public shape only: no key or reachable infrastructure is present. Startup
	// must not decrypt or contact anything; full validation remains on unlock.
	config := []byte(`{"version":2,"enrollment_config_file":"/fixture/not-provisioned.json"}`)
	testfixture.Must(t, os.WriteFile(configuration, config, 0600))
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "/portico", "agent", "daemon", "--config", configuration, "--socket", path)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		testfixture.Must(t, cmd.Start())
		joined := make(chan error, 1)
		go func() { joined <- cmd.Wait() }()
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Lstat(path); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				<-joined
				t.Fatal("daemon startup failed")
			}
			time.Sleep(time.Millisecond)
		}
		state, err := Status(ctx, path)
		testfixture.Must(t, err)
		if state != "locked" {
			cancel()
			<-joined
			t.Fatal("restart restored unlocked state")
		}
		testfixture.Must(t, cmd.Process.Signal(syscall.SIGTERM))
		err = <-joined
		cancel()
		if err != nil || out.String() != "Local agent daemon stopped.\n" || stderr.Len() != 0 {
			t.Fatalf("daemon shutdown: %v %q %q", err, out.String(), stderr.String())
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("daemon retained socket")
		}
		got, err := os.ReadFile(configuration)
		testfixture.Must(t, err)
		if !bytes.Equal(got, config) {
			t.Fatal("daemon rewrote public configuration")
		}
	}
}
