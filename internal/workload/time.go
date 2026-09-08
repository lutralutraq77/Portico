package workload

import (
	"math"
	"sync"
	"time"

	"portico.local/portico/internal/boottime"
)

// ClockHealth must read a trusted, current, nonblocking local health estimate.
// A missing/stale estimate returns an error. Linux callers may supply
// clockhealth.Uncertainty; their time service still requires qualification.
// Isolated tests explicitly supply fixture bounds.
type ClockHealth func() (uncertainty time.Duration, err error)

type sample struct {
	boot        time.Duration
	wall        time.Time
	uncertainty time.Duration
}
type clock struct {
	mu       sync.Mutex
	health   ClockHealth
	readBoot func() (time.Duration, error)
	readWall func() time.Time
	last     sample
	bad      bool
}

func newClock(health ClockHealth) *clock {
	return &clock{health: health, readBoot: boottime.Now, readWall: time.Now}
}
func (c *clock) now() (sample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bad || c.health == nil {
		return sample{}, ErrDenied
	}
	start, e := c.readBoot()
	wall := c.readWall().UTC()
	u, he := c.health()
	end, ee := c.readBoot()
	if e != nil || he != nil || ee != nil || start < 0 || end < start || end-start > 100*time.Millisecond || wall.IsZero() || u < 0 || u > 30*time.Second {
		c.bad = true
		return sample{}, ErrDenied
	}
	v := sample{start, wall, u + (end - start) + time.Millisecond}
	if !c.last.wall.IsZero() {
		delta := v.wall.Sub(c.last.wall) - (v.boot - c.last.boot)
		if v.boot < c.last.boot || v.wall.Before(c.last.wall) || delta > v.uncertainty+c.last.uncertainty+100*time.Millisecond || delta < -v.uncertainty-c.last.uncertainty-100*time.Millisecond {
			c.bad = true
			return sample{}, ErrDenied
		}
	}
	c.last = v
	return v, nil
}

// window anchors returned lifetime to request start, not response receipt.
// Uncertainty only shortens it. Wall bounds separately enforce absolute expiry.
func window(start, now sample, issued, end time.Time, maximum time.Duration) (time.Duration, error) {
	life := end.Sub(issued)
	if start.boot > now.boot || life <= 0 || life > maximum || issued.Before(start.wall.Add(-start.uncertainty)) || issued.After(now.wall.Add(now.uncertainty)) || !now.wall.Add(now.uncertainty).Before(end) {
		return 0, ErrDenied
	}
	life -= start.uncertainty + now.uncertainty
	if life <= 0 || start.boot > math.MaxInt64-time.Duration(life) {
		return 0, ErrDenied
	}
	deadline := start.boot + life
	if now.boot >= deadline {
		return 0, ErrDenied
	}
	return deadline, nil
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func minTick(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
