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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

// This activation-only configuration has no issuer, bootstrap or signing
// capability. It belongs on a separate private listener from administration.
type AdminRenewalActivationConfig struct {
	Host                        string
	ServerIdentity              tls.Certificate
	Trust                       *pki.Trust
	Timeout                     time.Duration
	MaxConnections, MaxRequests int
}

type AdminRenewalActivationServer struct {
	server      *http.Server
	cancel      context.CancelFunc
	requests    chan struct{}
	connections atomic.Int64
	limit       int64
}

type adminRenewalConnKey struct{}

func (s *Store) NewAdminRenewalActivationServer(c AdminRenewalActivationConfig) (*AdminRenewalActivationServer, error) {
	u, err := url.Parse("https://" + c.Host)
	if s == nil || c.Trust == nil || c.Trust.Profile() != pki.Administrator || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.MaxRequests < 1 || c.MaxRequests > 4 || c.MaxConnections < 1 || c.MaxConnections > 8 || c.MaxRequests > c.MaxConnections || err != nil || len(c.Host) > 253 || u.Host != c.Host || u.Host != strings.ToLower(u.Host) || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrInvalid
	}
	tc, err := s.AdminRenewalTLSConfig(c.ServerIdentity, c.Trust)
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(context.Background())
	v := &AdminRenewalActivationServer{cancel: cancel, requests: make(chan struct{}, c.MaxRequests), limit: int64(c.MaxConnections)}
	h := &http.Server{TLSConfig: tc, ReadHeaderTimeout: c.Timeout, ReadTimeout: c.Timeout, WriteTimeout: c.Timeout, IdleTimeout: c.Timeout, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	h.SetKeepAlivesEnabled(false)
	h.BaseContext = func(net.Listener) context.Context { return root }
	h.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		if real, ok := conn.(*tls.Conn); ok {
			return context.WithValue(ctx, adminRenewalConnKey{}, real)
		}
		return ctx
	}
	h.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		deny := func() { w.WriteHeader(http.StatusForbidden); _, _ = io.WriteString(w, `{"error":"request rejected"}`) }
		conn, ok := r.Context().Value(adminRenewalConnKey{}).(*tls.Conn)
		if !ok || r.Host != c.Host || r.URL.Path != adminrenewal.ActivatePath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Origin") != "https://"+c.Host || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
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
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, adminrenewal.MaxActivationBody))
		if err != nil {
			deny()
			return
		}
		var request adminrenewal.ActivateRequest
		if wire.Decode(body, &request) != nil || request.Version != adminrenewal.Version || !validID(request.RenewalID) || s.ActivateAdminRenewal(ctx, conn, c.Trust, request.RenewalID) != nil {
			deny()
			return
		}
		der, err := adminDER(ctx, conn)
		if err != nil {
			deny()
			return
		}
		result := adminrenewal.Activated{Version: adminrenewal.Version, RenewalID: request.RenewalID, CertificateSHA256: pki.Hash(der)}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > adminrenewal.MaxActivationBody {
			deny()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})
	v.server = h
	return v, nil
}

// Serve accepts only an explicitly supplied loopback listener. It cannot bind
// a public interface or serve dashboard, ordinary enrollment or issuer routes.
func (s *AdminRenewalActivationServer) Serve(l net.Listener) error {
	if s == nil || l == nil {
		return ErrDenied
	}
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return ErrDenied
	}
	return s.server.Serve(tls.NewListener(&adminRenewalListener{Listener: l, server: s}, s.server.TLSConfig))
}

func (s *AdminRenewalActivationServer) Close(ctx context.Context) error {
	s.cancel()
	return s.server.Shutdown(ctx)
}

type adminRenewalListener struct {
	net.Listener
	server *AdminRenewalActivationServer
}

func (l *adminRenewalListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		for {
			n := l.server.connections.Load()
			if n >= l.server.limit {
				_ = conn.Close()
				break
			}
			if l.server.connections.CompareAndSwap(n, n+1) {
				return &adminRenewalConnection{Conn: conn, server: l.server}, nil
			}
		}
	}
}

type adminRenewalConnection struct {
	net.Conn
	server *AdminRenewalActivationServer
	once   sync.Once
}

func (c *adminRenewalConnection) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.server.connections.Add(-1) })
	return err
}
