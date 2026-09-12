package workload

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

type DeviceControl interface {
	CheckConnector(context.Context, control.ConnectorCheck) (control.ConnectorStatus, error)
}
type ClientConfig struct {
	Control                       DeviceControl
	Devices, Connectors           *pki.Trust
	Identity                      tls.Certificate
	MaxConnections                int
	OperationTimeout, IdleTimeout time.Duration
	ClockHealth                   ClockHealth
}
type Client struct {
	config      ClientConfig
	identity    tls.Certificate
	credential  pki.Credential
	clock       *clock
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[*Conn]struct{}
	work        sync.WaitGroup
}

func NewClient(ctx context.Context, c ClientConfig) (*Client, error) {
	if ctx == nil || c.Control == nil || c.Devices == nil || c.Connectors == nil || c.Devices.Profile() != pki.Device || c.Connectors.Profile() != pki.Connector || c.Devices.DeploymentID() != c.Connectors.DeploymentID() || c.ClockHealth == nil || c.MaxConnections < 1 || c.MaxConnections > 64 || c.OperationTimeout <= 0 || c.OperationTimeout > 5*time.Second || c.IdleTimeout <= 0 || c.IdleTimeout > 15*time.Minute {
		return nil, ErrDenied
	}
	identity, e := c.Devices.TLSIdentity(c.Identity)
	if e != nil {
		return nil, ErrDenied
	}
	credential, e := c.Devices.VerifyPeer(identity.Certificate[0], time.Now())
	if e != nil {
		return nil, ErrDenied
	}
	root, cancel := context.WithCancel(ctx)
	v := &Client{config: c, identity: identity, credential: credential, clock: newClock(c.ClockHealth), ctx: root, cancel: cancel, connections: map[*Conn]struct{}{}}
	if _, e = v.clock.now(); e != nil {
		cancel()
		return nil, e
	}
	return v, nil
}
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	var list []*Conn
	for x := range c.connections {
		list = append(list, x)
	}
	c.mu.Unlock()
	c.cancel()
	for _, x := range list {
		_ = x.Close()
	}
	c.work.Wait()
}
func (c *Client) ActiveConnections() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.connections) }

// Open takes ownership of a paired carrier for this resource and its context.
// The returned Conn exposes no method that bypasses its forwarding checks.
func (c *Client) Open(ctx context.Context, raw net.Conn, r control.ResourceAccess) (*Conn, error) {
	if ctx == nil || raw == nil {
		return nil, ErrDenied
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	d := Destination{r.ID, r.Revision, r.Address, r.Port, r.Protocol}
	if !d.valid(nil) || !pki.ValidID(r.ConnectorID) {
		return nil, ErrDenied
	}
	now, e := c.clock.now()
	if e != nil {
		return nil, ErrDenied
	}
	tc, e := c.config.Connectors.ConnectorClientTLS(c.identity, r.ConnectorID)
	if e != nil {
		return nil, ErrDenied
	}
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil || len(c.connections) >= c.config.MaxConnections {
		c.mu.Unlock()
		return nil, ErrDenied
	}
	call, cancel := context.WithCancel(c.ctx)
	x := &Conn{owner: c, ctx: call, cancel: cancel, raw: raw, tls: tls.Client(raw, tc), resource: r, lease: now.boot + c.config.OperationTimeout, absoluteBoot: now.boot + time.Hour, absolute: earlier(c.credential.NotAfter, now.wall.Add(time.Hour)), idle: now.boot + c.config.IdleTimeout, done: make(chan struct{})}
	c.connections[x] = struct{}{}
	c.work.Add(1)
	c.mu.Unlock()
	stopCaller := context.AfterFunc(ctx, func() { _ = x.Close() })
	stopRoot := context.AfterFunc(c.ctx, func() { _ = x.Close() })
	x.work.Add(2)
	go x.supervise()
	// Join the open operation as well as the monitoring workers.
	go func() {
		x.work.Wait()
		if v, ok := raw.(interface{ Done() <-chan struct{} }); ok {
			<-v.Done()
		}
		stopCaller()
		stopRoot()
		c.mu.Lock()
		delete(c.connections, x)
		c.mu.Unlock()
		close(x.done)
		c.work.Done()
	}()
	defer x.work.Done()
	defer func() {
		if !success {
			_ = x.Close()
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(c.config.OperationTimeout))
	op, stop := context.WithTimeout(x.ctx, c.config.OperationTimeout)
	e = x.tls.HandshakeContext(op)
	stop()
	if e != nil {
		return nil, ErrDenied
	}
	state := x.tls.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, ErrDenied
	}
	x.peer, e = c.config.Connectors.Verify(state.PeerCertificates[0].Raw, r.ConnectorID, time.Now())
	if e != nil {
		return nil, ErrDenied
	}
	x.leaf = bytes.Clone(state.PeerCertificates[0].Raw)
	if e = x.check(true); e != nil {
		return nil, ErrDenied
	}
	if !x.allowed() {
		return nil, ErrDenied
	}
	if writeMessage(x.tls, openRequest{Version: version, ResourceID: r.ID, Revision: r.Revision}) != nil {
		return nil, ErrDenied
	}
	var response ready
	if readMessage(x.tls, &response) != nil || response.Version != version || !pki.ValidID(response.SessionID) || response.ResourceID != r.ID || response.Revision != r.Revision || !x.allowed() {
		return nil, ErrDenied
	}
	x.sessionID = response.SessionID
	_ = raw.SetDeadline(time.Time{})
	x.payload = newPayload(x.ctx, x.tls, raw)
	x.work.Add(1)
	go func() { defer x.work.Done(); <-x.payload.Done(); _ = x.Close() }()
	x.work.Add(1)
	go x.refresh()
	success = true
	return x, nil
}

type Conn struct {
	owner                           *Client
	ctx                             context.Context
	cancel                          context.CancelFunc
	raw                             net.Conn
	tls                             *tls.Conn
	payload                         *payloadConn
	peer                            pki.Credential
	leaf                            []byte
	resource                        control.ResourceAccess
	mu                              sync.Mutex
	once                            sync.Once
	closed                          bool
	lease, absoluteBoot, idle       time.Duration
	absolute                        time.Time
	connectorCertificate, sessionID string
	policyRevision                  int64
	work                            sync.WaitGroup
	done                            chan struct{}
}

func (x *Conn) Close() error {
	x.once.Do(func() { x.mu.Lock(); x.closed = true; x.mu.Unlock(); x.cancel(); _ = x.raw.Close() })
	return nil
}
func (x *Conn) Done() <-chan struct{}              { return x.done }
func (x *Conn) SessionID() string                  { return x.sessionID }
func (x *Conn) LocalAddr() net.Addr                { return x.raw.LocalAddr() }
func (x *Conn) RemoteAddr() net.Addr               { return x.raw.RemoteAddr() }
func (x *Conn) SetDeadline(t time.Time) error      { return x.raw.SetDeadline(t) }
func (x *Conn) SetReadDeadline(t time.Time) error  { return x.raw.SetReadDeadline(t) }
func (x *Conn) SetWriteDeadline(t time.Time) error { return x.raw.SetWriteDeadline(t) }
func (x *Conn) allowedAt(now sample) bool {
	return !x.closed && x.ctx.Err() == nil && now.boot < x.lease && now.boot < x.absoluteBoot && now.boot < x.idle && now.wall.Add(now.uncertainty).Before(x.absolute)
}
func (x *Conn) allowed() bool {
	now, e := x.owner.clock.now()
	if e != nil {
		_ = x.Close()
		return false
	}
	x.mu.Lock()
	ok := x.allowedAt(now)
	x.mu.Unlock()
	if !ok {
		_ = x.Close()
	}
	return ok
}
func (x *Conn) activity() bool {
	now, e := x.owner.clock.now()
	if e != nil {
		_ = x.Close()
		return false
	}
	x.mu.Lock()
	ok := x.allowedAt(now)
	if ok {
		x.idle = now.boot + x.owner.config.IdleTimeout
	}
	x.mu.Unlock()
	if !ok {
		_ = x.Close()
	}
	return ok
}
func (x *Conn) Read(p []byte) (int, error) {
	// Receiving FIN follows synchronous consumption of all prior framed DATA.
	// Preserve that zero-byte EOF even if carrier shutdown completed while the
	// caller was processing the last chunk. It grants no further read/write.
	if x.ReadFinished() {
		return 0, io.EOF
	}
	if !x.allowed() {
		return 0, ErrDenied
	}
	if len(p) > chunkSize {
		p = p[:chunkSize]
	}
	n, e := x.payload.Read(p)
	if n > 0 && !x.activity() {
		return 0, ErrDenied
	}
	return n, e
}

// ReadFinished reports a validated peer FIN after all preceding DATA was read.
// It does not imply a live lease, successful writes or renewed authority.
func (x *Conn) ReadFinished() bool { return x.payload != nil && x.payload.readFinished() }
func (x *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if !x.allowed() {
			return total, ErrDenied
		}
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		sent, e := x.payload.Write(p[:n])
		total += sent
		p = p[sent:]
		if sent > 0 && !x.activity() {
			return total, ErrDenied
		}
		if e != nil {
			return total, e
		}
		if sent == 0 {
			return total, ErrDenied
		}
	}
	return total, nil
}
func (x *Conn) CloseWrite() error {
	if !x.allowed() {
		return ErrDenied
	}
	return x.payload.CloseWrite()
}

// WaitWriteAcknowledged waits for the peer to consume all frames preceding our
// FIN. It grants no authority and must use a bounded caller context.
func (x *Conn) WaitWriteAcknowledged(ctx context.Context) error {
	if ctx == nil || x.payload == nil {
		return ErrDenied
	}
	return x.payload.waitAcknowledged(ctx)
}
func (x *Conn) supervise() {
	defer x.work.Done()
	var carrierDone <-chan struct{}
	if transport, ok := x.raw.(interface{ Done() <-chan struct{} }); ok {
		carrierDone = transport.Done()
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-carrierDone:
			// An unread application pipe can hide the framing reader's EOF.
			// The independent carrier lifecycle still terminates this stream.
			_ = x.Close()
			return
		case <-x.ctx.Done():
			_ = x.Close()
			return
		case <-tick.C:
			if !x.allowed() {
				return
			}
		}
	}
}
func (x *Conn) check(initial bool) error {
	if !x.allowed() {
		return ErrDenied
	}
	start, e := x.owner.clock.now()
	if e != nil {
		return ErrDenied
	}
	op, cancel := context.WithTimeout(x.ctx, x.owner.config.OperationTimeout)
	v, e := x.owner.config.Control.CheckConnector(op, control.ConnectorCheck{Version: 1, ResourceID: x.resource.ID, Revision: x.resource.Revision, ConnectorLeafDER: x.leaf})
	cancel()
	d := Destination{x.resource.ID, x.resource.Revision, x.resource.Address, x.resource.Port, x.resource.Protocol}
	if e != nil || v.Version != 1 || !pki.ValidID(v.ConnectorCertificateID) || v.PolicyRevision < 1 || !d.matches(v.Resource) || v.Resource.ConnectorID != x.resource.ConnectorID {
		return ErrDenied
	}
	now, e := x.owner.clock.now()
	if e != nil {
		return ErrDenied
	}
	end := earlier(v.Resource.Until, v.CheckedAt.Add(15*time.Second))
	end = earlier(end, earlier(x.peer.NotAfter, x.owner.credential.NotAfter))
	deadline, e := window(start, now, v.CheckedAt, end, 15*time.Second)
	if e != nil {
		return ErrDenied
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.allowedAt(now) || (!initial && (v.ConnectorCertificateID != x.connectorCertificate || v.PolicyRevision < x.policyRevision)) {
		return ErrDenied
	}
	x.connectorCertificate = v.ConnectorCertificateID
	x.policyRevision = v.PolicyRevision
	x.lease = deadline
	x.absolute = earlier(x.absolute, earlier(v.Resource.Until, x.peer.NotAfter))
	return nil
}
func (x *Conn) refresh() {
	defer x.work.Done()
	for {
		now, e := x.owner.clock.now()
		if e != nil {
			_ = x.Close()
			return
		}
		x.mu.Lock()
		delay := (x.lease - now.boot) / 3
		x.mu.Unlock()
		if delay > 5*time.Second {
			delay = 5 * time.Second
		}
		if delay < 25*time.Millisecond {
			_ = x.Close()
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-x.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if x.check(false) != nil {
			_ = x.Close()
			return
		}
	}
}
