package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/control"
)

type sessionBackend struct {
	catalog func(context.Context) ([]control.ResourceAccess, error)
}

func (b sessionBackend) Catalog(ctx context.Context) ([]control.ResourceAccess, error) {
	if b.catalog != nil {
		return b.catalog(ctx)
	}
	return []control.ResourceAccess{resource()}, nil
}
func (b sessionBackend) ConnectReady(context.Context, string, int64, client.Input, client.Output, func() error) error {
	return ErrRejected
}

func sessionFixture(t *testing.T, load identityLoader) (*manager, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	var now atomic.Int64
	var broken atomic.Bool
	now.Store(int64(time.Minute))
	m, err := makeManager(context.Background(), load, func() (time.Duration, error) {
		if broken.Load() {
			return 0, errors.New("synthetic unavailable boot clock")
		}
		return time.Duration(now.Load()), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.shutdown)
	return m, &now, &broken
}
func assertSessionState(t *testing.T, m *manager, expected pb.StateResponse_State) {
	t.Helper()
	r, err := m.state()
	if err != nil || r.State != expected {
		t.Fatalf("session state=%v err=%v want=%v", r, err, expected)
	}
}
func awaitSession(t *testing.T, done <-chan error, success bool) {
	t.Helper()
	select {
	case err := <-done:
		if (err == nil) != success {
			t.Fatalf("unexpected result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session worker not joined")
	}
}

func TestAgentSessionExplicitUnlockAndLock(t *testing.T) {
	var loads, calls atomic.Int64
	m, now, _ := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) {
		loads.Add(1)
		return sessionBackend{catalog: func(context.Context) ([]control.ResourceAccess, error) {
			calls.Add(1)
			return []control.ResourceAccess{resource()}, nil
		}}, nil
	})
	assertSessionState(t, m, pb.StateResponse_LOCKED)
	if _, err := m.Catalog(context.Background()); err == nil || loads.Load() != 0 || calls.Load() != 0 {
		t.Fatal("locked session admitted or loaded identity")
	}
	pass := []byte("synthetic-session-unlock-passphrase")
	if m.unlock(context.Background(), pass) != nil {
		t.Fatal("unlock rejected")
	}
	assertSessionState(t, m, pb.StateResponse_UNLOCKED)
	if m.unlock(context.Background(), pass) == nil || loads.Load() != 1 {
		t.Fatal("unlocked session silently replaced identity")
	}
	if _, err := m.Catalog(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("unlocked session did not reach backend")
	}
	if m.lock(context.Background()) != nil {
		t.Fatal("lock failed")
	}
	assertSessionState(t, m, pb.StateResponse_LOCKED)
	if _, err := m.Catalog(context.Background()); err == nil || calls.Load() != 1 {
		t.Fatal("locked identity reused")
	}
	now.Add(int64(2 * time.Second))
	if m.unlock(context.Background(), pass) != nil || loads.Load() != 2 {
		t.Fatal("explicit fresh unlock failed")
	}
}

func TestAgentLockCancelsPendingUnlockWithoutPublishing(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	var loads atomic.Int64
	m, _, _ := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) {
		if loads.Add(1) == 1 {
			close(entered)
		}
		<-finish // Models bounded KDF work that cannot stop mid-computation.
		return sessionBackend{}, nil
	})
	defer close(finish)
	done := make(chan error, 1)
	go func() { done <- m.unlock(context.Background(), []byte("synthetic-session-unlock-passphrase")) }()
	<-entered
	assertSessionState(t, m, pb.StateResponse_UNLOCKING)
	if m.unlock(context.Background(), []byte("synthetic-session-unlock-passphrase")) == nil || loads.Load() != 1 {
		t.Fatal("parallel KDF admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if m.lock(ctx) == nil {
		t.Fatal("lock claimed KDF joined before it exited")
	}
	// Complete the intentionally uncancellable loader before waiting for result.
	finish <- struct{}{}
	awaitSession(t, done, false)
	assertSessionState(t, m, pb.StateResponse_LOCKED)
	if m.valid() {
		t.Fatal("canceled unlock published identity")
	}
}

func TestAgentLockWaitsForOldKeyUsers(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	m, now, _ := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) {
		return sessionBackend{catalog: func(ctx context.Context) ([]control.ResourceAccess, error) {
			close(entered)
			<-ctx.Done()
			<-finish
			return []control.ResourceAccess{resource()}, nil // A canceled result must still fail.
		}}, nil
	})
	defer close(finish)
	if m.unlock(context.Background(), []byte("synthetic-session-unlock-passphrase")) != nil {
		t.Fatal("unlock failed")
	}
	done := make(chan error, 1)
	go func() { _, err := m.Catalog(context.Background()); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if m.lock(ctx) == nil {
		t.Fatal("lock returned before active backend joined")
	}
	assertSessionState(t, m, pb.StateResponse_DRAINING)
	now.Add(int64(2 * time.Second))
	if m.unlock(context.Background(), []byte("synthetic-session-unlock-passphrase")) == nil {
		t.Fatal("unlock overlapped old key users")
	}
	finish <- struct{}{}
	awaitSession(t, done, false)
	if m.lock(context.Background()) != nil {
		t.Fatal("completed drain did not join")
	}
	assertSessionState(t, m, pb.StateResponse_LOCKED)
}

func TestAgentSessionClockAndUnlockCancellation(t *testing.T) {
	for _, reason := range []string{"expiry", "backward", "unavailable", "canceled_unlock", "suspend_during_unlock"} {
		t.Run(reason, func(t *testing.T) {
			entered, finish := make(chan struct{}), make(chan struct{})
			m, now, broken := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) {
				close(entered)
				<-finish
				return sessionBackend{}, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- m.unlock(ctx, []byte("synthetic-session-unlock-passphrase")) }()
			<-entered
			if reason == "canceled_unlock" {
				cancel()
			}
			if reason == "suspend_during_unlock" {
				now.Add(int64(unlockTimeout))
			}
			close(finish)
			if reason == "canceled_unlock" || reason == "suspend_during_unlock" {
				awaitSession(t, done, false)
				assertSessionState(t, m, pb.StateResponse_LOCKED)
				return
			}
			awaitSession(t, done, true)
			switch reason {
			case "expiry":
				now.Add(int64(unlockLifetime))
			case "backward":
				now.Add(-1)
			case "unavailable":
				broken.Store(true)
			}
			if m.valid() {
				t.Fatal("invalid session clock retained authority")
			}
			if m.lock(context.Background()) != nil {
				t.Fatal("expired session did not join")
			}
			if reason != "expiry" {
				broken.Store(false)
				now.Add(int64(time.Hour))
				if m.healthy() || m.unlock(context.Background(), []byte("synthetic-session-unlock-passphrase")) == nil {
					t.Fatal("bad clock reopened daemon")
				}
			} else {
				assertSessionState(t, m, pb.StateResponse_LOCKED)
			}
		})
	}
}

func TestAgentFailedUnlockHasNoAutomaticRetry(t *testing.T) {
	var calls atomic.Int64
	m, now, _ := sessionFixture(t, func(context.Context, []byte) (resourceBackend, error) {
		calls.Add(1)
		return nil, errors.New("synthetic private loader failure")
	})
	pass := []byte("synthetic-session-unlock-passphrase")
	first := m.unlock(context.Background(), pass)
	second := m.unlock(context.Background(), pass)
	if first == nil || second == nil || calls.Load() != 1 {
		t.Fatal("failure retried without cooldown")
	}
	assertSessionState(t, m, pb.StateResponse_LOCKED)
	now.Add(int64(time.Second))
	if m.unlock(context.Background(), pass) == nil || calls.Load() != 2 {
		t.Fatal("explicit retry did not run")
	}
}
