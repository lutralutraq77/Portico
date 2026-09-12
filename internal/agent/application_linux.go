//go:build linux

package agent

import (
	"context"
	"net"
	"os/exec"
	"sync"
	"time"

	"portico.local/portico/internal/localipc"
)

const applicationStreams = 6

// RunApplication owns its new protected endpoint and all accepted streams.
// Success requires a successful child exit, at least one successful stream,
// and successful final RPC status for every accepted stream. Output EOF alone
// is insufficient. Cancellation joins the direct child and stream workers.
// This is a local launcher, not a sandbox for the selected executable.
func RunApplication(ctx context.Context, a Application) error {
	args, err := a.arguments()
	if err != nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	w, err := newWindow()
	if err != nil {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, unlockLifetime)
	defer cancel()
	l, err := localipc.Listen(a.Endpoint)
	if err != nil {
		return ErrRejected
	}
	defer l.Close()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if a.Stdin != nil {
		cmd.Stdin = a.Stdin
	}
	if a.Stdout != nil {
		cmd.Stdout = a.Stdout
	}
	if a.Stderr != nil {
		cmd.Stderr = a.Stderr
	}
	cmd.WaitDelay = operationTimeout
	if cmd.Start() != nil {
		return ErrRejected
	}
	child := make(chan error, 1)
	go func() { child <- cmd.Wait() }()
	// The acceptor holds at most one unadmitted connection and allocates no
	// worker before the supervisor has checked its fixed admission bound.
	incoming := make(chan *net.UnixConn)
	acceptDone := make(chan error, 1)
	stopAccept := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				select {
				case <-stopAccept:
					acceptDone <- nil
				default:
					acceptDone <- ErrRejected
				}
				return
			}
			u, ok := c.(*net.UnixConn)
			if !ok {
				_ = c.Close()
				acceptDone <- ErrRejected
				return
			}
			select {
			case incoming <- u:
			case <-stopAccept:
				_ = u.Close()
				acceptDone <- ErrRejected
				return
			}
		}
	}()
	type result struct {
		connection *net.UnixConn
		err        error
	}
	results := make(chan result, applicationStreams)
	active := make(map[*net.UnixConn]struct{})
	failed, succeeded, admissionClosed := false, false, false
	closeAdmission := func() {
		if !admissionClosed {
			admissionClosed = true
			close(stopAccept)
			if l.Close() != nil {
				failed = true
			}
		}
	}
	stop := func() {
		failed = true
		cancel()
		closeAdmission()
		for c := range active {
			_ = c.Close()
		}
	}
	canceled := ctx.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var drain *time.Timer
	var drainDeadline <-chan time.Time
	defer func() {
		if drain != nil {
			drain.Stop()
		}
	}()
	for child != nil || acceptDone != nil || len(active) != 0 {
		select {
		case c := <-incoming:
			if admissionClosed || ctx.Err() != nil || !w.valid() || len(active) == applicationStreams {
				_ = c.Close()
				stop()
				continue
			}
			active[c] = struct{}{}
			go func() {
				err := Connect(ctx, a.AgentSocket, a.ResourceID, a.Revision, &applicationInput{UnixConn: c}, &applicationOutput{UnixConn: c})
				_ = c.Close()
				results <- result{c, err}
			}()
		case r := <-results:
			delete(active, r.connection)
			if r.err != nil {
				stop()
			} else {
				succeeded = true
			}
		case err := <-child:
			child = nil
			closeAdmission()
			if err != nil {
				stop()
			} else if len(active) != 0 {
				drain = time.NewTimer(operationTimeout)
				drainDeadline = drain.C
			}
		case err := <-acceptDone:
			acceptDone = nil
			incoming = nil
			if err != nil {
				stop()
			}
		case <-canceled:
			canceled = nil
			stop()
		case <-drainDeadline:
			drainDeadline = nil
			stop()
		case <-tick.C:
			if !w.valid() {
				stop()
			}
		}
	}
	if failed || !succeeded || ctx.Err() != nil || !w.valid() {
		return ErrRejected
	}
	return nil
}

// The two owned directions must not close each other when FIN is observed.
// Connect may close each direction more than once while joining its workers.
type applicationInput struct {
	*net.UnixConn
	once sync.Once
	err  error
}

func (c *applicationInput) Close() error {
	c.once.Do(func() { c.err = c.CloseRead() })
	return c.err
}

type applicationOutput struct {
	*net.UnixConn
	once sync.Once
	err  error
}

func (c *applicationOutput) Close() error {
	c.once.Do(func() { c.err = c.CloseWrite() })
	return c.err
}
