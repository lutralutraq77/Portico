//go:build linux

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/testfixture"
)

type streamFunc func(context.Context, string, int64, client.Input, client.Output, func() error) error

func (f streamFunc) Catalog(context.Context) ([]control.ResourceAccess, error) {
	return []control.ResourceAccess{resource()}, nil
}
func (f streamFunc) ConnectReady(ctx context.Context, id string, revision int64, input client.Input, output client.Output, ready func() error) error {
	defer input.Close()
	defer output.Close()
	return f(ctx, id, revision, input, output, ready)
}

func echoStream(ctx context.Context, id string, revision int64, input client.Input, output client.Output, ready func() error) error {
	if id != resource().ID || revision != resource().Revision || ready() != nil {
		return ErrRejected
	}
	_, err := io.Copy(output, input)
	return err
}

func tunnelPipes(t *testing.T, path string) (net.Conn, net.Conn, <-chan error, context.CancelFunc) {
	t.Helper()
	input, appInput := net.Pipe()
	appOutput, output := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan error, 1)
	go func() { done <- Connect(ctx, path, resource().ID, resource().Revision, input, output) }()
	t.Cleanup(func() { cancel(); input.Close(); output.Close(); appInput.Close(); appOutput.Close() })
	testfixture.Must(t, appInput.SetDeadline(time.Now().Add(10*time.Second)))
	testfixture.Must(t, appOutput.SetDeadline(time.Now().Add(10*time.Second)))
	return appInput, appOutput, done, cancel
}

func expectTunnelEnd(t *testing.T, done <-chan error, success bool) {
	t.Helper()
	select {
	case err := <-done:
		if (err == nil) != success {
			t.Fatalf("tunnel success=%t error=%v", success, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel workers did not join")
	}
}

func TestGuestAgentTunnel(t *testing.T) {
	agentGuest(t)
	t.Run("exact_multichunk_transfer_and_final_success", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(echoStream))
		input, output, done, _ := tunnelPipes(t, path)
		payload := bytes.Repeat([]byte{0, 0xff, 1, 2, '\n'}, 60000)
		written := make(chan error, 1)
		go func() { _, err := input.Write(payload); input.Close(); written <- err }()
		got, err := io.ReadAll(output)
		testfixture.Must(t, err)
		testfixture.Must(t, <-written)
		if !bytes.Equal(got, payload) {
			t.Fatal("tunnel changed binary payload")
		}
		expectTunnelEnd(t, done, true)
	})
	t.Run("output_fin_does_not_close_input", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(func(_ context.Context, _ string, _ int64, input client.Input, output client.Output, ready func() error) error {
			if ready() != nil {
				return ErrRejected
			}
			if _, err := output.Write([]byte("response-before-input")); err != nil {
				return err
			}
			if output.Close() != nil {
				return ErrRejected
			}
			got, err := io.ReadAll(input)
			if err != nil || string(got) != "input-after-output-fin" {
				return ErrRejected
			}
			return nil
		}))
		input, output, done, _ := tunnelPipes(t, path)
		got, err := io.ReadAll(output)
		testfixture.Must(t, err)
		if string(got) != "response-before-input" {
			t.Fatal("missing output before FIN")
		}
		select {
		case <-done:
			t.Fatal("output FIN became final success")
		default:
		}
		_, err = input.Write([]byte("input-after-output-fin"))
		testfixture.Must(t, err)
		input.Close()
		expectTunnelEnd(t, done, true)
	})
	t.Run("late_failure_after_output_fin_is_not_success", func(t *testing.T) {
		fail := make(chan struct{})
		_, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, output client.Output, ready func() error) error {
			if ready() != nil {
				return ErrRejected
			}
			output.Close()
			select {
			case <-fail:
			case <-ctx.Done():
			}
			return errors.New("synthetic-sensitive-backend-detail")
		}))
		input, output, done, _ := tunnelPipes(t, path)
		_, err := io.ReadAll(output)
		testfixture.Must(t, err)
		select {
		case <-done:
			t.Fatal("FIN hid pending final status")
		default:
		}
		input.Close()
		close(fail)
		expectTunnelEnd(t, done, false)
	})
	t.Run("denial_does_not_read_application_input", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(func(context.Context, string, int64, client.Input, client.Output, func() error) error {
			return errors.New("synthetic-sensitive-backend-detail")
		}))
		input, _, done, _ := tunnelPipes(t, path)
		written := make(chan int, 1)
		go func() { n, _ := input.Write([]byte("must-not-be-read")); written <- n }()
		expectTunnelEnd(t, done, false)
		if <-written != 0 {
			t.Fatal("read application bytes before remote READY")
		}
	})
	for _, blocked := range []string{"recv", "send"} {
		t.Run("stop_joins_blocked_"+blocked, func(t *testing.T) {
			started, exited := make(chan struct{}), make(chan struct{})
			s, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, output client.Output, ready func() error) error {
				defer close(exited)
				if ready() != nil {
					return ErrRejected
				}
				close(started)
				if blocked == "send" {
					_, err := output.Write(make([]byte, 2*1024*1024))
					return err
				}
				<-ctx.Done()
				return ctx.Err()
			}))
			_, _, done, _ := tunnelPipes(t, path)
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("backend did not start")
			}
			stop := make(chan struct{})
			go func() { s.stop(); close(stop) }()
			select {
			case <-stop:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not join blocked workers")
			}
			select {
			case <-exited:
			default:
				t.Fatal("backend outlived shutdown")
			}
			if blocked == "send" {
				// A DATA delivery already blocked in application output expires
				// at the explicit five-second local write deadline.
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("stopped transfer succeeded")
					}
				case <-time.After(operationTimeout + 2*time.Second):
					t.Fatal("blocked output outlived its bounded delivery deadline")
				}
				return
			}
			expectTunnelEnd(t, done, false)
		})
	}
	t.Run("client_cancel_closes_blocked_application_pipes", func(t *testing.T) {
		started := make(chan struct{})
		_, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, output client.Output, ready func() error) error {
			if ready() != nil {
				return ErrRejected
			}
			close(started)
			_, err := output.Write(make([]byte, maxChunk))
			if err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}))
		_, _, done, cancel := tunnelPipes(t, path)
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("backend did not start")
		}
		cancel()
		expectTunnelEnd(t, done, false)
	})
	t.Run("actual_command_uses_only_application_pipes", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(echoStream))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/portico", "agent", "connect", "--socket", path, "--resource", resource().ID, "--revision", strconv.FormatInt(resource().Revision, 10))
		payload := bytes.Repeat([]byte{0, 0xff, 'c'}, 20000)
		cmd.Stdin = bytes.NewReader(payload) // os/exec supplies an actual pipe.
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		got, err := cmd.Output()
		if err != nil || stderr.Len() != 0 || !bytes.Equal(got, payload) {
			t.Fatalf("command failed: %v %q", err, stderr.String())
		}
	})
}

func TestGuestAgentTunnelRejectsProtocolAbuse(t *testing.T) {
	agentGuest(t)
	for _, name := range []string{"missing_open", "bad_version", "address_as_id", "extra_open_payload", "unknown_fields", "second_open", "client_fin_frame", "oversized_chunk", "data_before_open", "ready_from_client"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			_, path := serveFixture(t, streamFunc(func(ctx context.Context, id string, revision int64, input client.Input, output client.Output, ready func() error) error {
				calls.Add(1)
				return echoStream(ctx, id, revision, input, output, ready)
			}))
			c, err := newClient(path)
			testfixture.Must(t, err)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := pb.NewAgentClient(c).Connect(ctx)
			testfixture.Must(t, err)
			open := frame(pb.TunnelFrame_OPEN)
			open.ResourceId, open.Revision = resource().ID, resource().Revision
			later := name == "second_open" || name == "client_fin_frame" || name == "oversized_chunk" || name == "ready_from_client"
			switch name {
			case "bad_version":
				open.Version++
			case "address_as_id":
				open.ResourceId = "192.0.2.1:443"
			case "extra_open_payload":
				open.Data = []byte("secret")
			case "unknown_fields":
				open.ProtoReflect().SetUnknown([]byte{0x30, 1})
			case "data_before_open":
				open = frame(pb.TunnelFrame_DATA)
				open.Data = []byte("data")
			}
			if name != "missing_open" {
				testfixture.Must(t, stream.Send(open))
			}
			if later {
				r, err := stream.Recv()
				testfixture.Must(t, err)
				if !validFrame(r, pb.TunnelFrame_READY) {
					t.Fatal("missing READY")
				}
				switch name {
				case "client_fin_frame":
					open = frame(pb.TunnelFrame_FIN)
				case "oversized_chunk":
					open = frame(pb.TunnelFrame_DATA)
					open.Data = make([]byte, maxChunk+1)
				case "ready_from_client":
					open = frame(pb.TunnelFrame_READY)
				}
				testfixture.Must(t, stream.Send(open))
			}
			testfixture.Must(t, stream.CloseSend())
			r, err := stream.Recv()
			// Output may half-close before the rejected input's final status.
			// FIN is never success; consume it and require the denial trailer.
			if err == nil && validFrame(r, pb.TunnelFrame_FIN) {
				_, err = stream.Recv()
			}
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("protocol violation was accepted: %v", err)
			}
			if !later && calls.Load() != 0 {
				t.Fatal("invalid selection reached backend")
			}
		})
	}
}

func TestGuestAgentTunnelAdmission(t *testing.T) {
	agentGuest(t)
	t.Run("idle_open_has_bounded_lifetime", func(t *testing.T) {
		var calls atomic.Int64
		s, path := serveFixture(t, streamFunc(func(context.Context, string, int64, client.Input, client.Output, func() error) error {
			calls.Add(1)
			return ErrRejected
		}))
		c, err := newClient(path)
		testfixture.Must(t, err)
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		stream, err := pb.NewAgentClient(c).Connect(ctx)
		testfixture.Must(t, err)
		_, err = stream.Recv()
		if status.Code(err) != codes.PermissionDenied || calls.Load() != 0 {
			t.Fatalf("idle open did not expire before backend: %v", err)
		}
		s.stop()
		if s.requests.Load() != 0 {
			t.Fatal("idle receiver retained admission")
		}
	})
	t.Run("eight_active_streams_are_bounded_and_joined", func(t *testing.T) {
		var calls, active atomic.Int64
		s, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, _ client.Output, ready func() error) error {
			calls.Add(1)
			active.Add(1)
			defer active.Add(-1)
			if ready() != nil {
				return ErrRejected
			}
			<-ctx.Done()
			return ctx.Err()
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var clients []*grpc.ClientConn
		defer func() {
			for _, c := range clients {
				c.Close()
			}
		}()
		for range maxConnections {
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
				t.Fatal("admitted stream not ready")
			}
		}
		if s.requests.Load() != maxConnections || active.Load() != maxConnections {
			t.Fatal("fixture did not fill stream admission")
		}
		if _, err := Catalog(ctx, path); err == nil {
			t.Fatal("excess connection accepted")
		}
		if calls.Load() != maxConnections {
			t.Fatal("excess stream reached backend")
		}
		done := make(chan struct{})
		go func() { s.stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("admitted streams did not join")
		}
		if active.Load() != 0 || s.requests.Load() != 0 || s.connections.Load() != 0 {
			t.Fatal("stop retained stream resources")
		}
	})
}

type maliciousTunnel struct {
	pb.UnimplementedAgentServer
	scenario string
}

func (s maliciousTunnel) Connect(stream grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if s.scenario == "data_before_ready" {
		r := frame(pb.TunnelFrame_DATA)
		r.Data = []byte("unready")
		return stream.Send(r)
	}
	if err := stream.Send(frame(pb.TunnelFrame_READY)); err != nil {
		return err
	}
	if s.scenario == "missing_fin" {
		return nil
	}
	if err := stream.Send(frame(pb.TunnelFrame_FIN)); err != nil {
		return err
	}
	switch s.scenario {
	case "data_after_fin":
		r := frame(pb.TunnelFrame_DATA)
		r.Data = []byte("after-fin")
		return stream.Send(r)
	case "duplicate_fin":
		return stream.Send(frame(pb.TunnelFrame_FIN))
	case "late_failure":
		return rejected()
	}
	return nil
}

func TestGuestAgentTunnelRejectsFalseCompletion(t *testing.T) {
	agentGuest(t)
	for _, scenario := range []string{"data_before_ready", "missing_fin", "data_after_fin", "duplicate_fin", "late_failure"} {
		t.Run(scenario, func(t *testing.T) {
			path := socketPath(t)
			l, err := localipc.Listen(path)
			testfixture.Must(t, err)
			s := grpc.NewServer()
			pb.RegisterAgentServer(s, maliciousTunnel{scenario: scenario})
			joined := make(chan struct{})
			go func() { _ = s.Serve(l); close(joined) }()
			defer func() { s.Stop(); l.Close(); <-joined }()
			input, output, done, _ := tunnelPipes(t, path)
			input.Close()
			_, _ = io.ReadAll(output)
			expectTunnelEnd(t, done, false)
		})
	}
}

// Compile-time check: application adapters keep both deadlines and close.
var _ client.Input = (*os.File)(nil)
