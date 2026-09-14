package agent

import (
	"sync"
	"time"

	"portico.local/portico/internal/boottime"
)

// Unlock lifetime is process-local and includes suspend. A bad/decreasing
// reading permanently closes this window; it cannot be reset by a later sample.
type window struct {
	mu          sync.Mutex
	read        func() (time.Duration, error)
	start, last time.Duration
	closed      bool
}

func newWindow() (*window, error) { return makeWindow(boottime.Now) }
func makeWindow(read func() (time.Duration, error)) (*window, error) {
	start, err := read()
	if err != nil || start < 0 {
		return nil, ErrRejected
	}
	return &window{read: read, start: start, last: start}, nil
}
func (w *window) valid() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	now, err := w.read()
	if err != nil || now < w.last || now-w.start >= unlockLifetime {
		w.closed = true
		return false
	}
	w.last = now
	return true
}
