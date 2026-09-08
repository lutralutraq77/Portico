package workload

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

type session struct {
	server                                           *Server
	raw                                              net.Conn
	inner                                            *tls.Conn
	peer                                             pki.Credential
	destination                                      Destination
	ctx                                              context.Context
	cancel                                           context.CancelFunc
	mu                                               sync.Mutex
	stopOnce                                         sync.Once
	stopped, finished, joined, active                bool
	id, device, hostBinding                          string
	auth                                             control.Authorization
	destinationConn                                  net.Conn
	lease, activation, absoluteBoot, hostLease, idle time.Duration
	absolute, hostUntil                              time.Time
	done                                             chan struct{}
	work                                             sync.WaitGroup
}

func (x *session) stop() {
	x.stopOnce.Do(func() {
		x.mu.Lock()
		x.stopped = true
		destination := x.destinationConn
		x.mu.Unlock()
		x.cancel()
		// Closing the underlying stream avoids a blocking TLS close-notify on
		// revocation. Graceful half-close is handled only by the forwarding loop.
		_ = x.raw.Close()
		if destination != nil {
			_ = destination.Close()
		}
	})
}
func (x *session) allowedAt(now sample) bool {
	if x.stopped || x.ctx.Err() != nil || now.boot >= x.lease || !now.wall.Add(now.uncertainty).Before(x.absolute) {
		return false
	}
	if x.hostLease != 0 && now.boot >= x.hostLease {
		return false
	}
	if x.absoluteBoot != 0 && now.boot >= x.absoluteBoot {
		return false
	}
	if !x.active && x.activation != 0 && now.boot >= x.activation {
		return false
	}
	if x.active && now.boot >= x.idle {
		return false
	}
	return true
}
func (x *session) allowed() bool {
	now, e := x.server.clock.now()
	if e != nil {
		x.stop()
		return false
	}
	x.mu.Lock()
	ok := x.allowedAt(now)
	x.mu.Unlock()
	if !ok {
		x.stop()
	}
	return ok
}
func (x *session) supervise() {
	defer x.work.Done()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-x.ctx.Done():
			x.stop()
			return
		case <-tick.C:
			if !x.allowed() {
				return
			}
		}
	}
}
func (x *session) hosting(first bool) error {
	if !x.allowed() {
		return ErrDenied
	}
	start, e := x.server.clock.now()
	if e != nil {
		return ErrDenied
	}
	op, cancel := context.WithTimeout(x.ctx, x.server.config.OperationTimeout)
	v, e := x.server.config.Control.Hosting(op)
	cancel()
	if e != nil || !v.Valid() || v.ConnectorID != x.server.identity.PrincipalID || v.ConnectorCertificateID != x.server.config.CertificateID {
		return ErrDenied
	}
	now, e := x.server.clock.now()
	if e != nil {
		return ErrDenied
	}
	deadline, e := window(start, now, v.CheckedAt, v.Until, 15*time.Second)
	if e != nil {
		return ErrDenied
	}
	var selected *control.HostingResource
	for i := range v.Resources {
		if v.Resources[i].Resource.ID == x.destination.ResourceID {
			if selected != nil {
				return ErrDenied
			}
			selected = &v.Resources[i]
		}
	}
	if selected == nil || !x.destination.matches(selected.Resource) {
		return ErrDenied
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.allowedAt(now) || (!first && (selected.HostBindingID != x.hostBinding || v.PolicyRevision < x.auth.PolicyRevision)) {
		return ErrDenied
	}
	if first {
		x.hostBinding = selected.HostBindingID
		x.hostUntil = selected.Until
	} else {
		x.hostUntil = earlier(x.hostUntil, selected.Until)
	}
	x.hostLease = deadline
	return nil
}
func (x *session) accept(start sample, a control.Authorization, initial bool) error {
	now, e := x.server.clock.now()
	if e != nil {
		return ErrDenied
	}
	if !a.Valid() || !x.destination.matches(a.Resource) || a.DeviceID != x.peer.PrincipalID || a.ConnectorID != x.server.identity.PrincipalID || a.ConnectorCertificateID != x.server.config.CertificateID || a.SessionUntil.After(x.peer.NotAfter) || a.SessionUntil.After(x.server.identity.NotAfter) {
		return ErrDenied
	}
	lease, e := window(start, now, a.IssuedAt, a.LeaseUntil, 15*time.Second)
	if e != nil {
		return ErrDenied
	}
	absolute, e := window(start, now, a.IssuedAt, a.SessionUntil, time.Hour)
	if e != nil {
		return ErrDenied
	}
	activation, e := window(start, now, a.IssuedAt, a.ActivateUntil, 5*time.Second)
	if e != nil {
		return ErrDenied
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.allowedAt(now) || a.SessionUntil.After(x.hostUntil) {
		return ErrDenied
	}
	if initial {
		if a.Sequence != 1 || x.id != a.SessionID {
			return ErrDenied
		}
		x.absoluteBoot = absolute
		x.absolute = a.SessionUntil
		x.activation = activation
	} else {
		old := x.auth
		if a.SessionID != old.SessionID || a.CertificateID != old.CertificateID || a.Sequence <= old.Sequence || a.Sequence-old.Sequence != 1 || a.PolicyRevision < old.PolicyRevision || a.IssuedAt.Before(old.IssuedAt) || a.SessionUntil.After(x.absolute) {
			return ErrDenied
		}
		x.absoluteBoot = minTick(x.absoluteBoot, absolute)
		x.absolute = earlier(x.absolute, a.SessionUntil)
		if !x.active {
			x.active = true
			x.idle = now.boot + x.server.config.IdleTimeout
		}
	}
	x.auth = a
	x.lease = lease
	return nil
}
func (x *session) transition(activation bool) error {
	if !x.allowed() {
		return ErrDenied
	}
	start, e := x.server.clock.now()
	if e != nil {
		return ErrDenied
	}
	x.mu.Lock()
	r := control.SessionRequest{Version: 1, SessionID: x.id, Sequence: x.auth.Sequence}
	x.mu.Unlock()
	op, cancel := context.WithTimeout(x.ctx, x.server.config.OperationTimeout)
	var a control.Authorization
	if activation {
		a, e = x.server.config.Control.Activate(op, r)
	} else {
		a, e = x.server.config.Control.Renew(op, r)
	}
	cancel()
	if e != nil {
		return ErrDenied
	}
	return x.accept(start, a, false)
}
func (x *session) renew() {
	defer x.work.Done()
	for {
		now, e := x.server.clock.now()
		if e != nil {
			x.stop()
			return
		}
		x.mu.Lock()
		delay := (x.lease - now.boot) / 3
		x.mu.Unlock()
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		if delay < 25*time.Millisecond {
			x.stop()
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-x.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if x.hosting(false) != nil || x.transition(false) != nil {
			x.stop()
			return
		}
	}
}
func (x *session) activity() bool {
	now, e := x.server.clock.now()
	if e != nil {
		x.stop()
		return false
	}
	x.mu.Lock()
	ok := x.allowedAt(now)
	if ok {
		x.idle = now.boot + x.server.config.IdleTimeout
	}
	x.mu.Unlock()
	if !ok {
		x.stop()
	}
	return ok
}
func (x *session) copy(dst, src net.Conn) error {
	buffer := make([]byte, chunkSize)
	for {
		if !x.allowed() {
			return ErrDenied
		}
		n, e := src.Read(buffer)
		for sent := 0; sent < n; {
			if !x.allowed() {
				return ErrDenied
			}
			written, writeError := dst.Write(buffer[sent:n])
			if written > 0 {
				sent += written
				if !x.activity() {
					return ErrDenied
				}
			}
			if writeError != nil || written == 0 {
				return ErrDenied
			}
		}
		if e == io.EOF {
			if !x.allowed() {
				return ErrDenied
			}
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = dst.SetWriteDeadline(time.Now().Add(x.server.config.OperationTimeout))
				e := half.CloseWrite()
				// The application write direction is closed, but authenticated
				// framing acknowledgments may still be needed for the other FIN.
				_ = dst.SetWriteDeadline(time.Time{})
				return e
			}
			return ErrDenied
		}
		if e != nil || n == 0 {
			return ErrDenied
		}
	}
}
func (x *session) finish() {
	x.stop()
	x.work.Wait()
	joined := true
	if workers, ok := x.raw.(interface{ Done() <-chan struct{} }); ok {
		timer := time.NewTimer(x.server.config.OperationTimeout)
		select {
		case <-workers.Done():
		case <-timer.C:
			joined = false
		}
		timer.Stop()
	}
	x.mu.Lock()
	x.finished = true
	x.joined = joined
	id, seq := x.id, x.auth.Sequence
	x.mu.Unlock()
	close(x.done)
	x.server.signal()
	if id == "" {
		x.server.release(x)
		return
	}
	if seq < 1 {
		seq = 1
	}
	op, cancel := context.WithTimeout(x.server.ctx, x.server.config.OperationTimeout)
	_ = x.server.config.Control.CloseSession(op, control.SessionRequest{Version: 1, SessionID: id, Sequence: seq})
	cancel()
}
