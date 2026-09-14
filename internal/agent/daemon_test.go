package agent

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// This tests the supervision ordering independently of Unix transport and
// real boot-clock qualification, which remain covered by the Linux fixtures.
func TestDaemonSupervisionShutdownOrdering(t *testing.T) {
	for _, mode := range []string{"cancel_during_selected_health_tick", "clock_failure_during_cancellation", "unexpected_server_exit", "explicit_shutdown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m, err := makeManager(ctx, func(context.Context, []byte) (resourceBackend, error) { return sessionBackend{}, nil }, func() (time.Duration, error) { return time.Minute, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer m.shutdown()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			s := &server{grpc: grpc.NewServer()}
			defer s.stop()
			served := make(chan error, 1)
			go func() { served <- s.grpc.Serve(listener) }()
			ticks := make(chan time.Time)
			result := make(chan error, 1)
			go func() { result <- superviseLocked(ctx, m, s, served, ticks) }()
			if mode == "cancel_during_selected_health_tick" || mode == "clock_failure_during_cancellation" {
				// The unbuffered send proves select has chosen the tick while
				// this mutex prevents the manager from observing it yet.
				m.mu.Lock()
				select {
				case ticks <- time.Now():
				case <-time.After(3 * time.Second):
					m.mu.Unlock()
					t.Fatal("health tick was not selected")
				}
				if mode == "cancel_during_selected_health_tick" {
					cancel()
				} else {
					m.read = func() (time.Duration, error) { cancel(); return 0, errors.New("synthetic boot-clock failure") }
				}
				m.mu.Unlock()
			} else if mode == "unexpected_server_exit" {
				s.stop()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				wantSuccess := mode == "cancel_during_selected_health_tick" || mode == "explicit_shutdown"
				if (err == nil) != wantSuccess {
					t.Fatalf("supervision result=%v, want success=%t", err, wantSuccess)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("supervisor did not join")
			}
		})
	}
}
