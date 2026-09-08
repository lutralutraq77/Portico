// Package connector composes outbound carrier bindings with the exact-resource
// workload server. It opens no listener and restores no sessions after restart.
package connector

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/workload"
)

var ErrConfiguration = errors.New("invalid connector runtime configuration")

type Options struct {
	// Workers bounds all pending binds and active streams together, up to 64.
	Workers int
	// Retries apply to a new carrier binding only, never to application data or
	// a previous authorization. Failed/idle bindings back off up to RetryMax.
	RetryMin, RetryMax time.Duration
}

func (o Options) valid() bool {
	return o.Workers >= 1 && o.Workers <= 64 && o.RetryMin >= 250*time.Millisecond && o.RetryMin <= o.RetryMax && o.RetryMax <= 5*time.Second
}

// Run owns c and s once arguments validate, and closes/joins them before return.
// Their controller client remains caller-owned and must outlive Run. Cancellation
// is an ordinary shutdown; a clock-health failure returns an error and requires
// a new workload server. Clock-health recovery never revives the old server.
func Run(ctx context.Context, c *carrier.Client, s *workload.Server, o Options) error {
	if ctx == nil || c == nil || s == nil || !o.valid() {
		return ErrConfiguration
	}
	return run(ctx, o, dependencies{
		bind:  func(ctx context.Context) (connection, error) { return c.Bind(ctx, s.ConnectorID()) },
		serve: s.Serve, health: s.CheckHealth,
		closeCarrier: func() { _ = c.Close() }, closeServer: s.Close,
	})
}

type connection interface {
	net.Conn
	Done() <-chan struct{}
}
type dependencies struct {
	bind                      func(context.Context) (connection, error)
	serve                     func(context.Context, net.Conn) error
	health                    func() error
	closeCarrier, closeServer func()
}

func run(parent context.Context, o Options, d dependencies) error {
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		// Stop pending binds and raw streams first. Server.Close then closes
		// destinations and joins its forwarding/receipt workers. Each pool
		// worker separately joins its carrier, including rejected admissions.
		d.closeCarrier()
		d.closeServer()
		workers.Wait()
	}()
	if err := d.health(); err != nil {
		return err
	}
	if parent.Err() != nil {
		return nil
	}
	workers.Add(o.Workers)
	for i := 0; i < o.Workers; i++ {
		go func() {
			defer workers.Done()
			delay := o.RetryMin
			for ctx.Err() == nil {
				c, err := d.bind(ctx)
				if err == nil && c != nil {
					if ctx.Err() == nil {
						err = d.serve(ctx, c)
					}
					_ = c.Close()
					// Never reuse a slot before its old pumps join. A broken
					// implementation cannot silently release that obligation.
					<-c.Done()
					if err == nil {
						delay = o.RetryMin
					}
				}
				if ctx.Err() != nil {
					return
				}
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				if err != nil {
					delay = min(delay*2, o.RetryMax)
				}
			}
		}()
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := d.health(); err != nil {
				return err
			}
		}
	}
}
