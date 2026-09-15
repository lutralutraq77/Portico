package adminbridge

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/testfixture"
)

// Fixture readers are package-private and never configurable through the native
// browser or an on-disk profile. Changes share the guard's sampling lock.
type clockFixture struct {
	clock              *sessionClock
	boot               time.Duration
	wall               time.Time
	u                  time.Duration
	healthErr, bootErr error
	span               time.Duration
	read               int
}

func clockSeed() *clockFixture {
	f := &clockFixture{boot: time.Hour, wall: time.Now().UTC()}
	f.clock = &sessionClock{
		health:   func() (time.Duration, error) { return f.u, f.healthErr },
		readWall: func() time.Time { return f.wall },
		readBoot: func() (time.Duration, error) {
			f.read++
			if f.read%2 == 0 {
				return f.boot + f.span, f.bootErr
			}
			return f.boot, f.bootErr
		},
	}
	return f
}

func (f *clockFixture) change(fn func()) {
	f.clock.mu.Lock()
	defer f.clock.mu.Unlock()
	fn()
}

func (f *clockFixture) advance(d time.Duration) {
	f.change(func() { f.boot += d; f.wall = f.wall.Add(d) })
}

func (f *clockFixture) client(t *testing.T, config Config) *Client {
	t.Helper()
	c, err := newClient(context.Background(), config, f.clock)
	testfixture.Must(t, err)
	t.Cleanup(c.Close)
	return c
}

func TestSessionClockFaultsAreSticky(t *testing.T) {
	for _, scenario := range []string{"suspend_expired", "wall_rollback", "boot_rollback", "wall_jump", "boot_jump", "health_missing", "uncertainty_negative", "uncertainty_excess", "boot_error", "negative_boot", "zero_wall", "sample_rollback", "sample_slow"} {
		t.Run(scenario, func(t *testing.T) {
			f := clockSeed()
			_, err := f.clock.begin(time.Minute, f.wall.Add(-time.Hour), f.wall.Add(time.Hour))
			testfixture.Must(t, err)
			initialBoot, initialWall := f.boot, f.wall
			switch scenario {
			case "suspend_expired":
				f.advance(time.Minute)
			case "wall_rollback":
				f.wall = f.wall.Add(-time.Nanosecond)
			case "boot_rollback":
				f.boot--
			case "wall_jump":
				f.wall = f.wall.Add(time.Second)
			case "boot_jump":
				f.boot += time.Second
			case "health_missing":
				f.healthErr = errors.New("fixture unavailable")
			case "uncertainty_negative":
				f.u = -1
			case "uncertainty_excess":
				f.u = 30*time.Second + 1
			case "boot_error":
				f.bootErr = errors.New("fixture unavailable")
			case "negative_boot":
				f.boot = -1
			case "zero_wall":
				f.wall = time.Time{}
			case "sample_rollback":
				f.span = -1
			case "sample_slow":
				f.span = 100*time.Millisecond + 1
			}
			if _, _, err := f.clock.check(); err == nil {
				t.Fatal("unsafe sample accepted")
			}
			f.boot, f.wall, f.u, f.span, f.healthErr, f.bootErr = initialBoot, initialWall, 0, 0, nil, nil
			if _, _, err := f.clock.check(); err == nil {
				t.Fatal("failed session resumed after clock recovery")
			}
		})
	}
}

func TestSessionClockBoundsCannotExtend(t *testing.T) {
	f := clockSeed()
	_, err := f.clock.begin(time.Minute, f.wall.Add(-time.Hour), f.wall.Add(time.Hour))
	testfixture.Must(t, err)
	f.u = 2 * time.Second
	_, left, err := f.clock.check()
	testfixture.Must(t, err)
	if left != 58*time.Second-2*time.Millisecond {
		t.Fatalf("incorrect conservative lifetime: %s", left)
	}
	f.u = 0
	_, improved, err := f.clock.check()
	testfixture.Must(t, err)
	if improved != left {
		t.Fatal("improved UTC estimate extended session")
	}
	f.advance(left - time.Nanosecond)
	_, last, err := f.clock.check()
	testfixture.Must(t, err)
	if last != time.Nanosecond {
		t.Fatal("boot deadline moved")
	}
	f.advance(time.Nanosecond)
	if _, _, err := f.clock.check(); err == nil {
		t.Fatal("exact expiry boundary accepted")
	}

	for _, scenario := range []string{"not_yet_valid", "certificate_expired", "boot_overflow", "uncertainty_consumes_lifetime"} {
		t.Run(scenario, func(t *testing.T) {
			f := clockSeed()
			start, end := f.wall.Add(-time.Hour), f.wall.Add(time.Hour)
			life := time.Minute
			switch scenario {
			case "not_yet_valid":
				start = f.wall
			case "certificate_expired":
				end = f.wall.Add(time.Millisecond)
			case "boot_overflow":
				f.boot = math.MaxInt64 - time.Second
			case "uncertainty_consumes_lifetime":
				life = time.Millisecond
			}
			if _, err := f.clock.begin(life, start, end); err == nil {
				t.Fatal("invalid initial window accepted")
			}
		})
	}
	f = clockSeed()
	_, err = f.clock.begin(time.Minute, f.wall.Add(-time.Hour), f.wall.Add(10*time.Second))
	testfixture.Must(t, err)
	f.advance(10 * time.Second)
	if _, _, err := f.clock.check(); err == nil {
		t.Fatal("certificate expiry exceeded")
	}
}

func TestNativeExpiredClockRejectsBeforeTLS(t *testing.T) {
	server := bridgeSeed(t, nil)
	f := clockSeed()
	c := f.client(t, server.config)
	f.advance(time.Minute)
	r, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"})
	if err == nil || r.Status != 0 || len(r.Body) != 0 {
		t.Fatal("expired session exposed response")
	}
	if server.hits.Load() != 0 || server.signer.signs.Load() != 0 {
		t.Fatal("expired session reached TLS")
	}
	c.Close()
	select {
	case <-c.watchDone:
	default:
		t.Fatal("Close did not join clock watcher")
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (fn responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestNativeClockRecheckedAfterResponse(t *testing.T) {
	server := bridgeSeed(t, nil)
	f := clockSeed()
	c := f.client(t, server.config)
	// Deliberately ignore request cancellation, like bytes buffered before sleep.
	c.client.Transport = responseTransport(func(*http.Request) (*http.Response, error) {
		f.advance(time.Minute)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("private")), Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"},
			"Content-Security-Policy": {browserCSP}, "Referrer-Policy": {"no-referrer"}, "X-Frame-Options": {"DENY"},
		}}, nil
	})
	r, err := c.Exchange(context.Background(), Request{Method: "GET", Path: "/admin"})
	if err == nil || len(r.Body) != 0 || r.Status != 0 {
		t.Fatal("buffered response survived expiry")
	}
}

func TestNativeClockFaultClosesIdleAndPendingIO(t *testing.T) {
	for _, scenario := range []string{"greeting", "idle", "body", "pending_http", "blocked_response"} {
		t.Run(scenario, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			server := bridgeSeed(t, func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				if scenario == "pending_http" {
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte("private"))
			})
			f := clockSeed()
			c := f.client(t, server.config)
			p := pipeSeed(t, c)
			if scenario != "greeting" {
				p.hello(t, c.Origin())
			}
			if scenario == "body" {
				testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 1, Method: "POST", Path: "/api/v1/admin/policy/confirm", Length: 8}, []byte("{")))
			}
			if scenario == "pending_http" || scenario == "blocked_response" {
				testfixture.Must(t, writePacket(p.peer, PipeRequest{Version: 1, ID: 1, Method: "GET", Path: "/admin"}, nil))
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("request never reached server")
				}
				if scenario == "blocked_response" {
					// Reading only the prefix proves the HTTP response arrived and
					// leaves the pipe writer blocked on the framed response header.
					var prefix [4]byte
					_, err := io.ReadFull(p.peer, prefix[:])
					testfixture.Must(t, err)
				}
			}
			f.change(func() { f.healthErr = errors.New("fixture health lost") })
			if p.join(t) == nil {
				t.Fatal("clock failure reported clean close")
			}
			c.Close()
			select {
			case <-c.watchDone:
			default:
				t.Fatal("clock watcher survived Close")
			}
			if server.hits.Load() > 1 {
				t.Fatal("clock fault retried request")
			}
		})
	}
}
