package connector

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOptionsBounds(t *testing.T) {
	valid := Options{Workers: 2, RetryMin: 250 * time.Millisecond, RetryMax: time.Second}
	if !valid.valid() {
		t.Fatal("valid options rejected")
	}
	for _, o := range []Options{
		{}, {0, valid.RetryMin, valid.RetryMax}, {65, valid.RetryMin, valid.RetryMax},
		{1, 249 * time.Millisecond, time.Second}, {1, time.Second, 250 * time.Millisecond},
		{1, time.Second, 5*time.Second + 1},
	} {
		if o.valid() {
			t.Fatalf("accepted %+v", o)
		}
	}
	if !errors.Is(Run(context.Background(), nil, nil, valid), ErrConfiguration) {
		t.Fatal("nil runtime accepted")
	}
}

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not reach barrier")
	}
}

func TestPendingBindsBoundedAndJoinedOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active, peak, calls atomic.Int64
	ready := make(chan struct{})
	var readyOnce sync.Once
	var closedCarrier, closedServer atomic.Bool
	d := dependencies{
		bind: func(ctx context.Context) (connection, error) {
			calls.Add(1)
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			if n == 3 {
				readyOnce.Do(func() { close(ready) })
			}
			<-ctx.Done()
			active.Add(-1)
			return nil, ctx.Err()
		},
		serve:        func(context.Context, net.Conn) error { t.Error("unexpected Serve"); return nil },
		health:       func() error { return nil },
		closeCarrier: func() { closedCarrier.Store(true) }, closeServer: func() { closedServer.Store(true) },
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := run(ctx, Options{3, 250 * time.Millisecond, time.Second}, d); err != nil {
			t.Error(err)
		}
	}()
	wait(t, ready)
	cancel()
	wait(t, done)
	if active.Load() != 0 || peak.Load() != 3 || calls.Load() != 3 || !closedCarrier.Load() || !closedServer.Load() {
		t.Fatal("pool exceeded limit or returned before ownership joined")
	}
}

func TestBindingFailuresBackOffAndCancellationInterruptsDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan time.Time, 4)
	d := dependencies{
		bind:   func(context.Context) (connection, error) { called <- time.Now(); return nil, errors.New("offline") },
		health: func() error { return nil }, closeCarrier: func() {}, closeServer: func() {},
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = run(ctx, Options{1, 250 * time.Millisecond, time.Second}, d) }()
	var times []time.Time
	for i := 0; i < 3; i++ {
		select {
		case at := <-called:
			times = append(times, at)
		case <-time.After(3 * time.Second):
			t.Fatal("retry not attempted")
		}
	}
	if times[1].Sub(times[0]) < 250*time.Millisecond || times[2].Sub(times[1]) < 500*time.Millisecond {
		t.Fatal("failed binds bypassed exponential backoff")
	}
	start := time.Now()
	cancel()
	wait(t, done)
	if time.Since(start) >= 500*time.Millisecond {
		t.Fatal("cancellation waited out retry delay")
	}
	select {
	case <-called:
		t.Fatal("binding retried after cancellation")
	default:
	}
}

type heldConn struct {
	net.Conn
	closed chan struct{}
	done   chan struct{}
	once   sync.Once
}

func (c *heldConn) Close() error {
	c.once.Do(func() { _ = c.Conn.Close(); close(c.closed) })
	return nil
}
func (c *heldConn) Done() <-chan struct{} { return c.done }

func TestRejectedStreamKeepsSlotAndShutdownUntilCarrierJoined(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	c := &heldConn{Conn: a, closed: make(chan struct{}), done: make(chan struct{})}
	var calls atomic.Int64
	d := dependencies{
		bind:   func(context.Context) (connection, error) { calls.Add(1); return c, nil },
		serve:  func(context.Context, net.Conn) error { return errors.New("denied") },
		health: func() error { return nil }, closeCarrier: func() {}, closeServer: func() {},
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = run(ctx, Options{1, 250 * time.Millisecond, time.Second}, d) }()
	wait(t, c.closed)
	cancel()
	select {
	case <-done:
		t.Fatal("shutdown returned with carrier still running")
	case <-time.After(25 * time.Millisecond):
	}
	if calls.Load() != 1 {
		t.Fatal("unjoined carrier slot reused")
	}
	close(c.done)
	wait(t, done)
}

func TestIdleClockFailureStopsPoolAndDoesNotResume(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var bad atomic.Bool
	started := make(chan struct{})
	want := errors.New("clock lost synchronization")
	d := dependencies{
		bind: func(ctx context.Context) (connection, error) { close(started); <-ctx.Done(); return nil, ctx.Err() },
		health: func() error {
			if bad.Load() {
				return want
			}
			return nil
		},
		closeCarrier: func() {}, closeServer: func() {},
	}
	result := make(chan error, 1)
	go func() { result <- run(ctx, Options{1, 250 * time.Millisecond, time.Second}, d) }()
	wait(t, started)
	bad.Store(true)
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("lost health error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle unhealthy connector remained bound")
	}
	bad.Store(false)
	// Returning after all workers join is the restart boundary; no asynchronous
	// retry worker remains to react to recovery.
}

func TestUnhealthyStartupClosesWithoutBinding(t *testing.T) {
	want := errors.New("unhealthy startup")
	var closes int
	d := dependencies{
		bind:         func(context.Context) (connection, error) { t.Fatal("bound before healthy startup"); return nil, nil },
		health:       func() error { return want },
		closeCarrier: func() { closes++ }, closeServer: func() { closes++ },
	}
	if err := run(context.Background(), Options{1, 250 * time.Millisecond, time.Second}, d); !errors.Is(err, want) || closes != 2 {
		t.Fatalf("startup error=%v closes=%d", err, closes)
	}
}
