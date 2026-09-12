package agent

import (
	"context"
	"sync"
	"time"

	"portico.local/portico/internal/boottime"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/control"
)

const unlockTimeout = 90 * time.Second

type resourceBackend interface {
	catalogBackend
	streamBackend
}
type identityLoader func(context.Context, []byte) (resourceBackend, error)

type unlockedSession struct {
	backend resourceBackend
	ctx     context.Context
	cancel  context.CancelFunc
	started time.Duration
	workers sync.WaitGroup
	done    chan struct{}
}
type unlockAttempt struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started time.Duration
	done    chan struct{}
}

// manager never reloads a key automatically. Unlock is serialized with previous
// key users and pending KDF work. Closing a session detaches it before canceling
// its contexts, so a concurrent borrow cannot acquire the old identity.
type manager struct {
	mu                sync.Mutex
	root              context.Context
	load              identityLoader
	read              func() (time.Duration, error)
	last, nextAttempt time.Duration
	broken, closed    bool
	active, retiring  *unlockedSession
	pending           *unlockAttempt
}

func newManager(ctx context.Context, load identityLoader) (*manager, error) {
	return makeManager(ctx, load, boottime.Now)
}
func makeManager(ctx context.Context, load identityLoader, read func() (time.Duration, error)) (*manager, error) {
	if ctx == nil || ctx.Err() != nil || load == nil || read == nil {
		return nil, ErrRejected
	}
	now, err := read()
	if err != nil || now < 0 {
		return nil, ErrRejected
	}
	return &manager{root: ctx, load: load, read: read, last: now}, nil
}

// All clock observations are serialized. A missing/decreasing observation is
// sticky for this daemon process, including while it is locked.
func (m *manager) observeLocked() (time.Duration, bool) {
	if m.closed || m.broken || m.root.Err() != nil {
		m.invalidateLocked()
		return 0, false
	}
	now, err := m.read()
	if err != nil || now < m.last {
		m.broken = true
		m.invalidateLocked()
		return 0, false
	}
	m.last = now
	if m.active != nil && (now-m.active.started >= unlockLifetime || m.active.ctx.Err() != nil) {
		m.retireLocked()
	}
	if m.pending != nil && now-m.pending.started >= unlockTimeout {
		m.pending.cancel()
	}
	return now, true
}
func (m *manager) invalidateLocked() {
	m.retireLocked()
	if m.pending != nil {
		m.pending.cancel()
	}
}
func (m *manager) retireLocked() {
	if m.active == nil {
		return
	}
	s := m.active
	m.active, m.retiring = nil, s
	s.cancel()
	go func() {
		s.workers.Wait()
		m.mu.Lock()
		s.backend = nil
		if m.retiring == s {
			m.retiring = nil
		}
		close(s.done)
		m.mu.Unlock()
	}()
}
func (m *manager) valid() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.observeLocked()
	return ok && m.active != nil
}
func (m *manager) healthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.observeLocked()
	return ok
}

func (m *manager) unlock(ctx context.Context, passphrase []byte) error {
	if ctx == nil || ctx.Err() != nil || !validPassphrase(passphrase) {
		return ErrRejected
	}
	m.mu.Lock()
	now, ok := m.observeLocked()
	if !ok || m.active != nil || m.retiring != nil || m.pending != nil || now < m.nextAttempt {
		m.mu.Unlock()
		return ErrRejected
	}
	attemptContext, cancel := context.WithTimeout(ctx, unlockTimeout)
	stopRoot := context.AfterFunc(m.root, cancel)
	a := &unlockAttempt{ctx: attemptContext, cancel: cancel, started: now, done: make(chan struct{})}
	m.pending, m.nextAttempt = a, now+time.Second
	m.mu.Unlock()
	defer stopRoot()
	defer cancel()
	backend, err := m.load(attemptContext, passphrase)
	m.mu.Lock()
	defer m.mu.Unlock()
	defer close(a.done)
	now, ok = m.observeLocked()
	m.pending = nil
	if err != nil || backend == nil || !ok || a.ctx.Err() != nil || now-a.started >= unlockTimeout {
		return ErrRejected
	}
	sessionContext, sessionCancel := context.WithTimeout(m.root, unlockLifetime)
	m.active = &unlockedSession{backend: backend, ctx: sessionContext, cancel: sessionCancel, started: now, done: make(chan struct{})}
	return nil
}

// lock rejects new work immediately, then waits for old backend calls and any
// canceled KDF operation. A request timeout cannot republish the detached key.
func (m *manager) lock(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	m.mu.Lock()
	m.invalidateLocked()
	s, pending := m.retiring, m.pending
	m.mu.Unlock()
	if pending != nil {
		select {
		case <-pending.done:
		case <-ctx.Done():
			return ErrRejected
		}
	}
	if s != nil {
		select {
		case <-s.done:
		case <-ctx.Done():
			return ErrRejected
		}
	}
	return nil
}
func (m *manager) shutdown() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	_ = m.lock(context.Background())
}

func (m *manager) borrow(ctx context.Context) (resourceBackend, context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, nil, ErrRejected
	}
	m.mu.Lock()
	_, ok := m.observeLocked()
	if !ok || m.active == nil {
		m.mu.Unlock()
		return nil, nil, nil, ErrRejected
	}
	s := m.active
	s.workers.Add(1)
	backend := s.backend
	m.mu.Unlock()
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	return backend, call, func() { stop(); cancel(); s.workers.Done() }, nil
}
func (m *manager) Catalog(ctx context.Context) ([]control.ResourceAccess, error) {
	b, call, release, err := m.borrow(ctx)
	if err != nil {
		return nil, ErrRejected
	}
	defer release()
	rows, err := b.Catalog(call)
	if err != nil || call.Err() != nil || !m.valid() {
		return nil, ErrRejected
	}
	return rows, nil
}
func (m *manager) ConnectReady(ctx context.Context, id string, revision int64, input client.Input, output client.Output, ready func() error) error {
	b, call, release, err := m.borrow(ctx)
	if err != nil {
		return ErrRejected
	}
	defer release()
	err = b.ConnectReady(call, id, revision, input, output, func() error {
		if call.Err() != nil || !m.valid() {
			return ErrRejected
		}
		return ready()
	})
	if err != nil || call.Err() != nil || !m.valid() {
		return ErrRejected
	}
	return nil
}
