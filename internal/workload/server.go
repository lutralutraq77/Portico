package workload

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

type ConnectorControl interface {
	Hosting(context.Context) (control.HostingSnapshot, error)
	Authorize(context.Context, control.AuthorizeRequest) (control.Authorization, error)
	Activate(context.Context, control.SessionRequest) (control.Authorization, error)
	Renew(context.Context, control.SessionRequest) (control.Authorization, error)
	CloseSession(context.Context, control.SessionRequest) error
	Cancellations(context.Context, control.CancellationRequest) (control.CancellationBatch, error)
	AcknowledgeCancellation(context.Context, control.CancellationAck) error
}
type ServerConfig struct {
	Control                        ConnectorControl
	Devices, Connectors            *pki.Trust
	Identity                       tls.Certificate
	CertificateID                  string
	Approved                       []Destination
	ProtectedNetworks              []netip.Prefix
	MaxSessions, MaxDeviceSessions int
	OperationTimeout, IdleTimeout  time.Duration
	ClockHealth                    ClockHealth
}
type Server struct {
	config   ServerConfig
	tls      *tls.Config
	identity pki.Credential
	approved map[string]Destination
	clock    *clock
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	states   map[*session]struct{}
	wake     chan struct{}
	work     sync.WaitGroup
}
type Stats struct{ Connections, PendingReceipts int }

// ConnectorID is taken from the validated local connector certificate.
func (s *Server) ConnectorID() string { return s.identity.PrincipalID }

// CheckHealth also checks idle servers. A failure latches the clock closed so
// later recovery cannot resume this runtime's old authority.
func (s *Server) CheckHealth() error {
	if s.ctx.Err() != nil {
		return ErrDenied
	}
	_, err := s.clock.now()
	return err
}

func NewServer(ctx context.Context, c ServerConfig) (*Server, error) {
	if ctx == nil || c.Control == nil || !pki.ValidID(c.CertificateID) || c.Devices == nil || c.Connectors == nil || c.ClockHealth == nil || len(c.Approved) == 0 || len(c.Approved) > 64 || len(c.ProtectedNetworks) == 0 || len(c.ProtectedNetworks) > 256 || c.MaxSessions < 1 || c.MaxSessions > 64 || c.MaxDeviceSessions < 1 || c.MaxDeviceSessions > c.MaxSessions || c.OperationTimeout <= 0 || c.OperationTimeout > 5*time.Second || c.IdleTimeout <= 0 || c.IdleTimeout > 15*time.Minute {
		return nil, ErrDenied
	}
	for _, p := range c.ProtectedNetworks {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return nil, ErrDenied
		}
	}
	tc, e := c.Connectors.ConnectorServerTLS(c.Identity, c.Devices)
	if e != nil {
		return nil, ErrDenied
	}
	identity, e := c.Connectors.VerifyPeer(c.Identity.Certificate[0], time.Now())
	if e != nil {
		return nil, ErrDenied
	}
	approved := map[string]Destination{}
	for _, d := range c.Approved {
		if !d.valid(c.ProtectedNetworks) {
			return nil, ErrDenied
		}
		if _, ok := approved[d.ResourceID]; ok {
			return nil, ErrDenied
		}
		approved[d.ResourceID] = d
	}
	root, cancel := context.WithCancel(ctx)
	s := &Server{config: c, tls: tc, identity: identity, approved: approved, clock: newClock(c.ClockHealth), ctx: root, cancel: cancel, states: map[*session]struct{}{}, wake: make(chan struct{}, 1)}
	if _, e = s.clock.now(); e != nil {
		cancel()
		return nil, e
	}
	s.work.Add(1)
	go func() { defer s.work.Done(); s.cancellations() }()
	return s, nil
}
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v Stats
	for x := range s.states {
		x.mu.Lock()
		if x.finished {
			v.PendingReceipts++
		} else {
			v.Connections++
		}
		x.mu.Unlock()
	}
	return v
}
func (s *Server) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	var list []*session
	for x := range s.states {
		list = append(list, x)
	}
	s.mu.Unlock()
	s.cancel()
	for _, x := range list {
		x.stop()
	}
	s.work.Wait()
}
func (s *Server) admit(raw net.Conn) (*session, error) {
	now, e := s.clock.now()
	if e != nil || raw == nil {
		return nil, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || len(s.states) >= s.config.MaxSessions {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithCancel(s.ctx)
	x := &session{server: s, raw: raw, ctx: ctx, cancel: cancel, lease: now.boot + s.config.OperationTimeout, absolute: now.wall.Add(s.config.OperationTimeout), done: make(chan struct{})}
	s.states[x] = struct{}{}
	s.work.Add(1)
	return x, nil
}
func (s *Server) identify(x *session, device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for other := range s.states {
		other.mu.Lock()
		if other.device == device && !other.finished {
			n++
		}
		other.mu.Unlock()
	}
	if n >= s.config.MaxDeviceSessions {
		return false
	}
	x.mu.Lock()
	x.device = device
	x.mu.Unlock()
	return true
}
func (s *Server) release(x *session) { s.mu.Lock(); delete(s.states, x); s.mu.Unlock(); s.signal() }

func (s *Server) bindID(x *session, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other := range s.states {
		other.mu.Lock()
		same := other.id == id
		other.mu.Unlock()
		if same {
			return false
		}
	}
	x.mu.Lock()
	x.id = id
	x.mu.Unlock()
	s.signal()
	return true
}

// Serve owns one paired byte stream. It starts no listener and can dial only a
// configured literal after online authorization. Return joins forwarding work.
func (s *Server) Serve(ctx context.Context, raw net.Conn) error {
	if ctx == nil || raw == nil {
		return ErrDenied
	}
	x, e := s.admit(raw)
	if e != nil {
		_ = raw.Close()
		return e
	}
	defer s.work.Done()
	stopCaller := context.AfterFunc(ctx, x.stop)
	defer stopCaller()
	stopRoot := context.AfterFunc(s.ctx, x.stop)
	defer stopRoot()
	x.work.Add(1)
	go x.supervise()
	defer x.finish()
	_ = raw.SetDeadline(time.Now().Add(s.config.OperationTimeout))
	x.inner = tls.Server(raw, s.tls)
	op, cancel := context.WithTimeout(x.ctx, s.config.OperationTimeout)
	e = x.inner.HandshakeContext(op)
	cancel()
	if e != nil {
		return ErrDenied
	}
	state := x.inner.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ErrDenied
	}
	peer, e := s.config.Devices.VerifyPeer(state.PeerCertificates[0].Raw, time.Now())
	if e != nil || !s.identify(x, peer.PrincipalID) {
		return ErrDenied
	}
	x.peer = peer
	var request openRequest
	if readMessage(x.inner, &request) != nil || request.Version != version || !pki.ValidID(request.ResourceID) || request.Revision < 1 {
		return ErrDenied
	}
	d, ok := s.approved[request.ResourceID]
	if !ok || d.Revision != request.Revision {
		return ErrDenied
	}
	x.destination = d
	if e = x.hosting(true); e != nil {
		return ErrDenied
	}
	start, e := s.clock.now()
	if e != nil {
		return ErrDenied
	}
	op, cancel = context.WithTimeout(x.ctx, s.config.OperationTimeout)
	a, e := s.config.Control.Authorize(op, control.AuthorizeRequest{Version: 1, ClientLeafDER: state.PeerCertificates[0].Raw, ResourceID: d.ResourceID, Revision: d.Revision})
	cancel()
	if e != nil {
		return ErrDenied
	}
	// Track the authenticated controller's session before validation/dialing,
	// so a later failure still attempts closure without claiming app activity.
	if !pki.ValidID(a.SessionID) || !s.bindID(x, a.SessionID) {
		return ErrDenied
	}
	if e = x.accept(start, a, true); e != nil {
		return ErrDenied
	}
	if !x.allowed() {
		return ErrDenied
	}
	op, cancel = context.WithTimeout(x.ctx, s.config.OperationTimeout)
	destination, e := (&net.Dialer{Timeout: s.config.OperationTimeout}).DialContext(op, "tcp", net.JoinHostPort(d.Address, strconv.Itoa(d.Port)))
	cancel()
	if e != nil {
		return ErrDenied
	}
	x.mu.Lock()
	if x.stopped {
		x.mu.Unlock()
		_ = destination.Close()
		return ErrDenied
	}
	x.destinationConn = destination
	x.mu.Unlock()
	if e = x.hosting(false); e != nil {
		return ErrDenied
	}
	if e = x.transition(true); e != nil {
		return ErrDenied
	}
	if !x.allowed() {
		return ErrDenied
	}
	if writeMessage(x.inner, ready{Version: version, SessionID: a.SessionID, ResourceID: d.ResourceID, Revision: d.Revision}) != nil {
		return ErrDenied
	}
	_ = raw.SetDeadline(time.Time{})
	payload := newPayload(x.ctx, x.inner, raw)
	x.work.Add(1)
	go func() { defer x.work.Done(); <-payload.Done(); x.stop() }()
	x.work.Add(1)
	go x.renew()
	results := make(chan error, 2)
	x.work.Add(2)
	go func() { defer x.work.Done(); results <- x.copy(destination, payload) }()
	go func() { defer x.work.Done(); results <- x.copy(payload, destination) }()
	first := <-results
	if first != nil {
		x.stop()
	}
	second := <-results
	if first != nil || second != nil {
		return ErrDenied
	}
	op, cancel = context.WithTimeout(x.ctx, s.config.OperationTimeout)
	defer cancel()
	return payload.waitAcknowledged(op)
}

func (s *Server) cancellations() {
	for s.ctx.Err() == nil {
		s.mu.Lock()
		var list []*session
		for x := range s.states {
			list = append(list, x)
		}
		s.mu.Unlock()
		owned := map[string]*session{}
		for _, x := range list {
			x.mu.Lock()
			id := x.id
			x.mu.Unlock()
			if id != "" {
				owned[id] = x
			}
		}
		if len(owned) == 0 {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		ids := make([]string, 0, len(owned))
		for id := range owned {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		op, cancel := context.WithTimeout(s.ctx, s.config.OperationTimeout)
		request := control.CancellationRequest{Version: 1, Limit: 64, WaitMillis: 1000, SessionIDs: ids}
		batch, e := s.config.Control.Cancellations(op, request)
		cancel()
		if e == nil && (!batch.ValidFor(request) || batch.ConnectorCertificateID != s.config.CertificateID) {
			e = ErrDenied
		}
		if e != nil {
			for _, x := range list {
				x.stop()
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		for _, item := range batch.Items {
			x, ok := owned[item.SessionID]
			if !ok {
				for _, x := range list {
					x.stop()
				}
				break
			}
			x.stop()
			// Never report an unknown session or one whose workers have not
			// joined. A later poll retries after local finish closes done.
			select {
			case <-x.done:
				x.mu.Lock()
				joined := x.joined
				x.mu.Unlock()
				if !joined {
					continue
				}
				op, cancel := context.WithTimeout(s.ctx, s.config.OperationTimeout)
				e = s.config.Control.AcknowledgeCancellation(op, control.CancellationAck{Version: 1, SessionID: item.SessionID})
				cancel()
				if e == nil {
					s.release(x)
				}
			default:
			}
		}
		// A full repeated batch must not spin while a local close/receipt is
		// pending. A new session or completed close wakes the bounded wait.
		if len(batch.Items) > 0 {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
}
