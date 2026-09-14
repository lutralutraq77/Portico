package adminbridge

import (
	"math"
	"sync"
	"time"

	"portico.local/portico/internal/boottime"
	"portico.local/portico/internal/clockhealth"
)

// ClockHealth reads a trusted, current, nonblocking UTC uncertainty estimate.
// Missing or stale information must return an error. A nil callback selects the
// operating-system reader; only isolated fixtures should supply synthetic bounds.
type ClockHealth func() (time.Duration, error)

type clockSample struct {
	boot        time.Duration
	wall        time.Time
	uncertainty time.Duration
}

type sessionClock struct {
	mu             sync.Mutex
	health         ClockHealth
	readBoot       func() (time.Duration, error)
	readWall       func() time.Time
	last           clockSample
	start          clockSample
	notBefore, end time.Time
	deadline       time.Duration
	bad            bool
}

func newSessionClock(health ClockHealth) *sessionClock {
	if health == nil {
		health = clockhealth.Uncertainty
	}
	return &sessionClock{health: health, readBoot: boottime.Now, readWall: time.Now}
}

// sample is called with mu held. UTC is stripped of Go's monotonic component:
// the independent boot clock includes suspend, unlike ordinary process timers.
func (c *sessionClock) sample() (clockSample, error) {
	if c.bad {
		return clockSample{}, ErrRejected
	}
	start, e := c.readBoot()
	wall := c.readWall().UTC()
	u, he := c.health()
	end, ee := c.readBoot()
	if e != nil || he != nil || ee != nil || start < 0 || end < start || end-start > 100*time.Millisecond || wall.IsZero() || u < 0 || u > 30*time.Second {
		c.bad = true
		return clockSample{}, ErrRejected
	}
	v := clockSample{start, wall, u + (end - start) + time.Millisecond}
	if !c.last.wall.IsZero() {
		// Check order before subtraction to keep duration arithmetic bounded.
		if v.boot < c.last.boot || v.wall.Before(c.last.wall) {
			c.bad = true
			return clockSample{}, ErrRejected
		}
		delta := v.wall.Sub(c.last.wall) - (v.boot - c.last.boot)
		bound := v.uncertainty + c.last.uncertainty + 100*time.Millisecond
		if delta > bound || delta < -bound {
			c.bad = true
			return clockSample{}, ErrRejected
		}
	}
	c.last = v
	return v, nil
}

func (c *sessionClock) begin(lifetime time.Duration, notBefore, notAfter time.Time) (clockSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.sample()
	if err != nil || lifetime <= 0 || lifetime > 10*time.Minute || !c.start.wall.IsZero() || v.boot > math.MaxInt64-lifetime {
		c.bad = true
		return clockSample{}, ErrRejected
	}
	c.start, c.notBefore, c.end = v, notBefore, v.wall.Add(lifetime)
	if notAfter.Before(c.end) {
		c.end = notAfter
	}
	c.deadline = v.boot + lifetime
	if _, err := c.remaining(v); err != nil {
		return clockSample{}, err
	}
	return v, nil
}

// remaining only shortens the original boot deadline, including when the UTC
// uncertainty estimate later improves. Expiry and every clock fault are sticky.
func (c *sessionClock) remaining(v clockSample) (time.Duration, error) {
	if c.bad || c.start.wall.IsZero() || v.wall.Add(-v.uncertainty).Before(c.notBefore) || !v.wall.Add(v.uncertainty).Before(c.end) {
		c.bad = true
		return 0, ErrRejected
	}
	life := c.end.Sub(c.start.wall) - c.start.uncertainty - v.uncertainty
	if life <= 0 || c.start.boot > math.MaxInt64-life {
		c.bad = true
		return 0, ErrRejected
	}
	c.deadline = min(c.deadline, c.start.boot+life)
	wallLeft := c.end.Sub(v.wall.Add(v.uncertainty))
	// Avoid adding a large duration after an injected/failed boot reading.
	if v.boot > math.MaxInt64-wallLeft {
		c.bad = true
		return 0, ErrRejected
	}
	c.deadline = min(c.deadline, v.boot+wallLeft)
	if v.boot >= c.deadline {
		c.bad = true
		return 0, ErrRejected
	}
	return c.deadline - v.boot, nil
}

func (c *sessionClock) check() (clockSample, time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.sample()
	if err != nil {
		return clockSample{}, 0, err
	}
	left, err := c.remaining(v)
	return v, left, err
}
