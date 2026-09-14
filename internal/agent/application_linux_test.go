//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/testfixture"
)

type applicationRun struct {
	done   chan struct{}
	err    error
	output *os.File
	cancel context.CancelFunc
	logs   bytes.Buffer
}

func applicationFixture(t *testing.T, agentSocket, mode string) Application {
	t.Helper()
	t.Setenv("PORTICO_APPLICATION_FIXTURE", mode)
	return Application{AgentSocket: agentSocket, Endpoint: socketPath(t), ResourceID: resource().ID, Revision: resource().Revision,
		Argv: []string{"/tests/agent", "-test.run=^TestGuestAgentApplication$", "--", "literal ; $(not-a-shell)", "{socket}"}}
}

func startApplication(t *testing.T, a Application, command bool) *applicationRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	r, w, err := os.Pipe()
	testfixture.Must(t, err)
	p := &applicationRun{done: make(chan struct{}), output: r, cancel: cancel}
	go func() {
		if command {
			args := []string{"agent", "exec", "--socket", a.AgentSocket, "--resource", a.ResourceID, "--revision", strconv.FormatInt(a.Revision, 10), "--endpoint", a.Endpoint, "--"}
			cmd := exec.CommandContext(ctx, "/portico", append(args, a.Argv...)...)
			cmd.Stdout, cmd.Stderr, cmd.WaitDelay = w, &p.logs, 5*time.Second
			p.err = cmd.Run()
		} else {
			a.Stdout = w
			p.err = RunApplication(ctx, a)
		}
		_ = w.Close()
		close(p.done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = r.Close()
		select {
		case <-p.done:
		case <-time.After(6 * time.Second):
			t.Error("application/stream workers did not join")
		}
	})
	return p
}

func (p *applicationRun) end(t *testing.T, success bool) {
	t.Helper()
	select {
	case <-p.done:
		if (p.err == nil) != success {
			t.Fatalf("application success=%t error=%v stderr=%q", success, p.err, p.logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("application completion exceeded fixture bound")
	}
}

func TestGuestAgentApplication(t *testing.T) {
	agentGuest(t)
	if mode := os.Getenv("PORTICO_APPLICATION_FIXTURE"); mode != "" {
		if applicationProcess(mode) != nil {
			os.Exit(7)
		}
		os.Exit(0)
	}
	for _, command := range []bool{false, true} {
		t.Run(fmt.Sprintf("exact_binary_transfer_and_cleanup_cli_%t", command), func(t *testing.T) {
			var calls atomic.Int64
			_, path := serveFixture(t, streamFunc(func(ctx context.Context, id string, revision int64, input client.Input, output client.Output, ready func() error) error {
				calls.Add(1)
				return echoStream(ctx, id, revision, input, output, ready)
			}))
			a := applicationFixture(t, path, "echo")
			p := startApplication(t, a, command)
			p.end(t, true)
			if calls.Load() != 2 {
				t.Fatal("application did not authorize each connection separately")
			}
			if _, err := os.Lstat(a.Endpoint); !os.IsNotExist(err) {
				t.Fatal("application endpoint was retained")
			}
		})
	}
	t.Run("output_fin_keeps_input_open", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(func(_ context.Context, _ string, _ int64, input client.Input, output client.Output, ready func() error) error {
			if ready() != nil || output.Close() != nil {
				return ErrRejected
			}
			b, err := io.ReadAll(input)
			if err != nil || string(b) != "after-fin" {
				return ErrRejected
			}
			return nil
		}))
		startApplication(t, applicationFixture(t, path, "half-close"), false).end(t, true)
	})
	t.Run("successful_child_cannot_hide_late_rpc_failure", func(t *testing.T) {
		release := make(chan struct{})
		_, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, output client.Output, ready func() error) error {
			if ready() != nil || output.Close() != nil {
				return ErrRejected
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return ErrRejected
		}))
		p := startApplication(t, applicationFixture(t, path, "fin"), false)
		testfixture.Must(t, p.output.SetReadDeadline(time.Now().Add(10*time.Second)))
		var marker [1]byte
		_, err := io.ReadFull(p.output, marker[:])
		testfixture.Must(t, err)
		if marker[0] != 'F' {
			t.Fatal("child did not observe output FIN")
		}
		line, err := bufio.NewReader(p.output).ReadString('\n')
		testfixture.Must(t, err)
		pid, err := strconv.Atoi(line[:len(line)-1])
		testfixture.Must(t, err)
		if pid <= 1 {
			t.Fatal("invalid fixture child pid")
		}
		deadline := time.Now().Add(3 * time.Second)
		for unix.Kill(pid, 0) != unix.ESRCH {
			if time.Now().After(deadline) {
				t.Fatal("successful child was not reaped before final RPC status")
			}
			time.Sleep(5 * time.Millisecond)
		}
		select {
		case <-p.done:
			t.Fatal("child completion hid pending final status")
		case <-time.After(100 * time.Millisecond):
		}
		close(release)
		p.end(t, false)
	})
	t.Run("child_failure_is_not_stream_success", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(echoStream))
		startApplication(t, applicationFixture(t, path, "failure"), true).end(t, false)
	})
	t.Run("unused_endpoint_is_not_success", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(echoStream))
		startApplication(t, applicationFixture(t, path, "unused"), false).end(t, false)
	})
	t.Run("cancellation_joins_child_and_stream", func(t *testing.T) {
		ready := make(chan struct{})
		_, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, _ client.Output, signal func() error) error {
			if signal() != nil {
				return ErrRejected
			}
			close(ready)
			<-ctx.Done()
			return ErrRejected
		}))
		a := applicationFixture(t, path, "hold")
		p := startApplication(t, a, false)
		testfixture.Must(t, p.output.SetReadDeadline(time.Now().Add(10*time.Second)))
		line, err := bufio.NewReader(p.output).ReadString('\n')
		testfixture.Must(t, err)
		pid, err := strconv.Atoi(line[:len(line)-1])
		testfixture.Must(t, err)
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("child never reached resource READY")
		}
		p.cancel()
		p.end(t, false)
		if unix.Kill(pid, 0) != unix.ESRCH {
			t.Fatal("direct child was not reaped")
		}
		if _, err := os.Lstat(a.Endpoint); !os.IsNotExist(err) {
			t.Fatal("cancel retained application listener")
		}
	})
	t.Run("six_stream_bound_rejects_seventh_without_authority", func(t *testing.T) {
		var calls atomic.Int64
		_, path := serveFixture(t, streamFunc(func(ctx context.Context, _ string, _ int64, _ client.Input, output client.Output, ready func() error) error {
			calls.Add(1)
			if ready() != nil {
				return ErrRejected
			}
			if _, err := output.Write([]byte{'R'}); err != nil {
				return err
			}
			<-ctx.Done()
			return ErrRejected
		}))
		startApplication(t, applicationFixture(t, path, "overflow"), false).end(t, false)
		if calls.Load() != 6 {
			t.Fatalf("backend admissions=%d, want six", calls.Load())
		}
	})
	t.Run("existing_endpoint_preserved", func(t *testing.T) {
		_, path := serveFixture(t, streamFunc(echoStream))
		a := applicationFixture(t, path, "echo")
		testfixture.Must(t, os.WriteFile(a.Endpoint, []byte("preserve"), 0600))
		startApplication(t, a, false).end(t, false)
		b, err := os.ReadFile(a.Endpoint)
		testfixture.Must(t, err)
		if string(b) != "preserve" {
			t.Fatal("existing endpoint was changed")
		}
	})
}

// Runs only as an explicitly selected child of the guarded guest test. It is
// an ordinary Unix client; the parent alone owns the agent RPC and its status.
func applicationProcess(mode string) error {
	if len(os.Args) < 4 || os.Args[len(os.Args)-2] != "literal ; $(not-a-shell)" {
		return ErrRejected
	}
	if mode == "unused" {
		return nil
	}
	path := os.Args[len(os.Args)-1]
	dial := func() (*net.UnixConn, error) {
		c, err := localipc.Dial(context.Background(), path)
		if err != nil {
			return nil, err
		}
		u := c.(*net.UnixConn)
		if u.SetDeadline(time.Now().Add(15*time.Second)) != nil {
			_ = u.Close()
			return nil, ErrRejected
		}
		return u, nil
	}
	if mode == "overflow" {
		for i := 0; i < 7; i++ {
			c, err := dial()
			if err != nil {
				return err
			}
			defer c.Close()
			var b [1]byte
			_, err = io.ReadFull(c, b[:])
			if i == 6 && err != nil {
				return nil
			}
			if err != nil || b[0] != 'R' {
				return ErrRejected
			}
		}
		return ErrRejected
	}
	count := 1
	if mode == "echo" {
		count = 2
	}
	for i := 0; i < count; i++ {
		c, err := dial()
		if err != nil {
			return err
		}
		defer c.Close()
		switch mode {
		case "hold":
			_, _ = fmt.Fprintln(os.Stdout, os.Getpid())
			_, err = io.ReadAll(c)
			return err
		case "half-close", "fin":
			_, err = io.ReadAll(c)
			if err != nil {
				return err
			}
			if mode == "half-close" {
				if _, err := c.Write([]byte("after-fin")); err != nil {
					return err
				}
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "F%d\n", os.Getpid())
			}
			return c.CloseWrite()
		case "echo", "failure":
			payload := bytes.Repeat([]byte{0, 1, 0xff, '\n'}, 10000)
			if _, err := c.Write(payload); err != nil {
				return err
			}
			if c.CloseWrite() != nil {
				return ErrRejected
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) || mode == "failure" {
				return ErrRejected
			}
		default:
			return ErrRejected
		}
	}
	return nil
}
