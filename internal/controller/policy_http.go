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
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

type PolicyHTTPConfig struct {
	Profile               pki.Profile
	Host                  string
	ServerIdentity        tls.Certificate
	AdministratorTrust    *pki.Trust
	AdministratorVerifier *adminauth.Verifier
}
type PolicyHTTPServer struct{ server *http.Server }
type policyConnKey struct{}
type previewApprovalRequest struct{ ID, Digest string }
type finishApprovalRequest struct {
	ID       string
	Response json.RawMessage
}

// NewHTTPServer owns both the TLS policy and connection context. No handler can
// authenticate from caller-supplied ConnectionState, usernames or proxy headers.
// The administrative HTTP surface is a private server component; browser/native
// delivery and platform-key isolation still require their dedicated qualification.
func (p *PolicyEngine) NewHTTPServer(c PolicyHTTPConfig) (*PolicyHTTPServer, error) {
	u, e := url.Parse("https://" + c.Host)
	if e != nil || u.Host != c.Host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ToLower(c.Host) != c.Host {
		return nil, ErrInvalid
	}
	var tc *tls.Config
	switch c.Profile {
	case pki.Device:
		tc, e = p.store.ClientTLSConfig(c.ServerIdentity, p.config.DeviceTrust, false)
	case pki.Connector:
		tc, e = p.store.ClientTLSConfig(c.ServerIdentity, p.config.ConnectorTrust, false)
	case pki.Administrator:
		if c.AdministratorVerifier == nil || c.AdministratorVerifier.Origin() != "https://"+c.Host {
			return nil, ErrInvalid
		}
		tc, e = p.store.AdminTLSConfig(c.ServerIdentity, c.AdministratorTrust)
	default:
		return nil, ErrInvalid
	}
	if e != nil {
		return nil, e
	}
	s := &http.Server{TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	s.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if conn, ok := c.(*tls.Conn); ok {
			return context.WithValue(ctx, policyConnKey{}, conn)
		}
		return ctx
	}
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		deny := func() { w.WriteHeader(http.StatusForbidden); _, _ = io.WriteString(w, `{"error":"request rejected"}`) }
		conn, ok := r.Context().Value(policyConnKey{}).(*tls.Conn)
		if !ok || r.Host != c.Host || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			deny()
			return
		}
		if c.Profile == pki.Administrator && r.Header.Get("Origin") != "https://"+c.Host {
			deny()
			return
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, wire.MaxBody))
		if e != nil {
			deny()
			return
		}
		var result any
		switch {
		case c.Profile == pki.Device && r.URL.Path == "/api/v1/device/catalog":
			var request struct{}
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			var resources []ResourceAccess
			resources, e = p.Catalog(r.Context(), conn)
			result = control.CatalogSnapshot{Version: control.Version, Resources: resources}
		case c.Profile == pki.Device && r.URL.Path == "/api/v1/device/check-connector":
			var request ConnectorCheck
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.CheckConnector(r.Context(), conn, request)
		case c.Profile == pki.Connector && r.URL.Path == "/api/v1/connector/hosting":
			var request struct{}
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.Hosting(r.Context(), conn)
		case c.Profile == pki.Connector && r.URL.Path == "/api/v1/connector/cancellations":
			var request CancellationRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.Cancellations(r.Context(), conn, request)
		case c.Profile == pki.Connector && r.URL.Path == "/api/v1/connector/acknowledge-cancellation":
			var request CancellationAck
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			e = p.AcknowledgeCancellation(r.Context(), conn, request)
			result = struct{}{}
		case c.Profile == pki.Connector && r.URL.Path == "/api/v1/connector/authorize":
			var request AuthorizeRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.Authorize(r.Context(), conn, request)
		case c.Profile == pki.Connector && (r.URL.Path == "/api/v1/connector/activate" || r.URL.Path == "/api/v1/connector/renew" || r.URL.Path == "/api/v1/connector/close"):
			var request SessionRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			switch r.URL.Path {
			case "/api/v1/connector/activate":
				result, e = p.Activate(r.Context(), conn, request)
			case "/api/v1/connector/renew":
				result, e = p.Renew(r.Context(), conn, request)
			default:
				e = p.CloseSession(r.Context(), conn, request)
				result = struct{}{}
			}
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/dashboard/inventory":
			var request DashboardRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.store.DashboardInventory(r.Context(), conn, c.AdministratorTrust, request)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/policy/preview":
			var request PolicyDraft
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.Preview(r.Context(), conn, c.AdministratorTrust, request)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/policy/challenge":
			var request previewApprovalRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.BeginPolicyApproval(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.ID, request.Digest)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/policy/confirm":
			var request finishApprovalRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			e = p.FinishPolicyApproval(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.ID, request.Response)
			result = struct{}{}
		default:
			deny()
			return
		}
		if e != nil {
			deny()
			return
		}
		encoded, e := json.Marshal(result)
		if e != nil || len(encoded) > wire.MaxBody {
			deny()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	})
	return &PolicyHTTPServer{server: s}, nil
}

// Serve is limited to explicitly supplied loopback listeners until deployment
// isolation is configured and tested. Calling this never creates a listener.
func (s *PolicyHTTPServer) Serve(l net.Listener) error {
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return ErrDenied
	}
	return s.server.Serve(tls.NewListener(l, s.server.TLSConfig))
}
func (s *PolicyHTTPServer) Close(ctx context.Context) error { return s.server.Shutdown(ctx) }
