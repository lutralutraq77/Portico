package controller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	enroll "portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

type EnrollmentHTTPConfig struct {
	Host           string
	ServerIdentity tls.Certificate
	Trust          *pki.Trust
	// Only the redemption server receives an issuance provider. The activation
	// server rejects configurations that carry a signer/provider capability.
	Provider                    IssuanceProvider
	Timeout                     time.Duration
	MaxConnections, MaxRequests int
}
type EnrollmentHTTPServer struct {
	server      *http.Server
	cancel      context.CancelFunc
	requests    chan struct{}
	connections atomic.Int64
	limit       int64
}
type EnrollmentHTTPStats struct {
	Connections int64
	Requests    int
}
type enrollmentConnKey struct{}

func (s *Store) NewEnrollmentRedemptionServer(c EnrollmentHTTPConfig) (*EnrollmentHTTPServer, error) {
	if c.Provider == nil {
		return nil, ErrInvalid
	}
	return s.newEnrollmentHTTP(c, false)
}
func (s *Store) NewEnrollmentActivationServer(c EnrollmentHTTPConfig) (*EnrollmentHTTPServer, error) {
	if c.Provider != nil {
		return nil, ErrInvalid
	}
	return s.newEnrollmentHTTP(c, true)
}

func (s *Store) newEnrollmentHTTP(c EnrollmentHTTPConfig, activation bool) (*EnrollmentHTTPServer, error) {
	u, err := url.Parse("https://" + c.Host)
	if s == nil || c.Trust == nil || (c.Trust.Profile() != pki.Device && c.Trust.Profile() != pki.Connector) || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.MaxRequests < 1 || c.MaxRequests > 8 || c.MaxConnections < 1 || c.MaxConnections > 32 || c.MaxRequests > c.MaxConnections || len(c.ServerIdentity.Certificate) == 0 || c.ServerIdentity.PrivateKey == nil || err != nil || u.Host != c.Host || u.Host != strings.ToLower(u.Host) || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrInvalid
	}
	_, port, err := net.SplitHostPort(c.Host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return nil, ErrInvalid
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.ServerIdentity}, ClientAuth: tls.NoClientCert, SessionTicketsDisabled: true}
	if activation {
		tc, err = s.ClientTLSConfig(c.ServerIdentity, c.Trust, true)
		if err != nil {
			return nil, err
		}
	}
	root, cancel := context.WithCancel(context.Background())
	v := &EnrollmentHTTPServer{cancel: cancel, requests: make(chan struct{}, c.MaxRequests), limit: int64(c.MaxConnections)}
	h := &http.Server{TLSConfig: tc, ReadHeaderTimeout: c.Timeout, ReadTimeout: c.Timeout, WriteTimeout: c.Timeout, IdleTimeout: c.Timeout, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	h.SetKeepAlivesEnabled(false)
	h.BaseContext = func(net.Listener) context.Context { return root }
	h.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		if real, ok := conn.(*tls.Conn); ok {
			return context.WithValue(ctx, enrollmentConnKey{}, real)
		}
		return ctx
	}
	h.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		deny := func() { w.WriteHeader(http.StatusForbidden); _, _ = io.WriteString(w, `{"error":"request rejected"}`) }
		conn, ok := r.Context().Value(enrollmentConnKey{}).(*tls.Conn)
		path := enroll.RedeemPath
		if activation {
			path = enroll.ActivatePath
		}
		if !ok || r.Host != c.Host || r.URL.Path != path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			deny()
			return
		}
		select {
		case v.requests <- struct{}{}:
		default:
			deny()
			return
		}
		defer func() { <-v.requests }()
		ctx, stop := context.WithTimeout(r.Context(), c.Timeout)
		defer stop()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, enroll.MaxBody))
		if err != nil {
			deny()
			return
		}
		defer clear(body)
		var result any
		if activation {
			var request enroll.ActivateRequest
			if wire.Decode(body, &request) != nil || request.Version != enroll.Version || !validID(request.InvitationID) {
				deny()
				return
			}
			if s.ActivateEnrollment(ctx, request.InvitationID, conn, c.Trust) != nil {
				deny()
				return
			}
			result = enroll.Activated{Version: enroll.Version, InvitationID: request.InvitationID}
		} else {
			var request enroll.RedeemRequest
			if wire.Decode(body, &request) != nil || !request.Valid() {
				deny()
				return
			}
			actor := c.Trust.IssuerID()
			if s.reserveEnrollment(ctx, actor, request.InvitationID, request.Secret, request.AttemptID, request.CSR, c.Trust) != nil {
				deny()
				return
			}
			der, err := s.EnrollmentCertificate(ctx, actor, request.InvitationID, request.Secret, request.AttemptID, request.CSR)
			if err != nil {
				// IssueEnrollment arbitrates the durable reserved -> issuing
				// transition. Concurrent/uncertain attempts never sign again.
				if s.IssueEnrollment(ctx, actor, request.InvitationID, c.Trust, c.Provider) != nil {
					deny()
					return
				}
				der, err = s.EnrollmentCertificate(ctx, actor, request.InvitationID, request.Secret, request.AttemptID, request.CSR)
				if err != nil {
					deny()
					return
				}
			}
			result = enroll.CertificateResponse{Version: enroll.Version, InvitationID: request.InvitationID, AttemptID: request.AttemptID, CertificateDER: der}
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > enroll.MaxBody || ctx.Err() != nil {
			deny()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})
	v.server = h
	return v, nil
}

// The development ingress accepts only a supplied loopback listener. It owns
// no public registration, resource, administrator or generic CA-sign endpoint.
func (s *EnrollmentHTTPServer) Serve(l net.Listener) error {
	if s == nil || l == nil {
		return ErrDenied
	}
	a, ok := l.Addr().(*net.TCPAddr)
	if !ok || !a.IP.IsLoopback() {
		return ErrDenied
	}
	return s.server.Serve(tls.NewListener(&enrollmentListener{Listener: l, server: s}, s.server.TLSConfig))
}
func (s *EnrollmentHTTPServer) Close(ctx context.Context) error {
	s.cancel()
	return s.server.Shutdown(ctx)
}
func (s *EnrollmentHTTPServer) Stats() EnrollmentHTTPStats {
	return EnrollmentHTTPStats{Connections: s.connections.Load(), Requests: len(s.requests)}
}

type enrollmentListener struct {
	net.Listener
	server *EnrollmentHTTPServer
}

func (l *enrollmentListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		for {
			n := l.server.connections.Load()
			if n >= l.server.limit {
				_ = c.Close()
				break
			}
			if l.server.connections.CompareAndSwap(n, n+1) {
				return &enrollmentConnection{Conn: c, server: l.server}, nil
			}
		}
	}
}

type enrollmentConnection struct {
	net.Conn
	server *EnrollmentHTTPServer
	once   sync.Once
}

func (c *enrollmentConnection) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.server.connections.Add(-1) })
	return err
}
