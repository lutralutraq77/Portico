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
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

type PolicyHTTPConfig struct {
	Profile                    pki.Profile
	Host                       string
	ServerIdentity             tls.Certificate
	AdministratorTrust         *pki.Trust
	AdministratorVerifier      *adminauth.Verifier
	AdministratorRenewalIssuer IssuanceProvider
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
	return p.newHTTPServer(c, nil)
}

// NewManagementHTTPServer adds the exact administrator-only resource gate to
// every TLS handshake and every request transaction. It is a distinct private
// destination; ordinary device/connector HTTP constructors cannot select it.
func (p *PolicyEngine) NewManagementHTTPServer(c PolicyHTTPConfig, route *ManagementRoute) (*PolicyHTTPServer, error) {
	if p == nil || route == nil || route.store != p.store || c.Profile != pki.Administrator || c.AdministratorTrust != route.config.Administrators || route.config.Connectors != p.config.ConnectorTrust {
		return nil, ErrInvalid
	}
	return p.newHTTPServer(c, route)
}

func (p *PolicyEngine) newHTTPServer(c PolicyHTTPConfig, route *ManagementRoute) (*PolicyHTTPServer, error) {
	if c.Profile != pki.Administrator && c.AdministratorRenewalIssuer != nil {
		return nil, ErrInvalid
	}
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
	if route != nil {
		verify := tc.VerifyConnection
		tc.VerifyConnection = func(state tls.ConnectionState) error {
			if err := verify(state); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return p.store.Update(ctx, route.config.ConnectorID, func(t *Tx) error {
				_, err := route.check(t, state.PeerCertificates[0].Raw)
				return err
			})
		}
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
		if c.Profile == pki.Administrator {
			w.Header().Set("Content-Security-Policy", dashboardCSP)
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Frame-Options", "DENY")
		}
		deny := func() { w.WriteHeader(http.StatusForbidden); _, _ = io.WriteString(w, `{"error":"request rejected"}`) }
		conn, ok := r.Context().Value(policyConnKey{}).(*tls.Conn)
		if !ok || r.Host != c.Host || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Header.Get("Content-Encoding") != "" {
			deny()
			return
		}
		if route != nil {
			bound, err := route.requestContext(r.Context(), conn)
			if err != nil {
				deny()
				return
			}
			r = r.WithContext(bound)
		}
		if r.Method == http.MethodGet {
			if c.Profile != pki.Administrator || p.store.serveDashboardAsset(w, r, conn, c) != nil {
				deny()
			}
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
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
		case c.Profile == pki.Administrator && c.AdministratorRenewalIssuer != nil && r.URL.Path == adminrenewal.PreparePath:
			var request adminrenewal.PrepareRequest
			if wire.Decode(body, &request) != nil || request.Version != adminrenewal.Version || request.PolicyRevision < 1 {
				deny()
				return
			}
			result, e = p.store.beginAdminRenewal(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.RenewalID, AdminRenewalSpec{CSR: request.CSR, NotAfter: request.NotAfter}, request.PolicyRevision)
		case c.Profile == pki.Administrator && c.AdministratorRenewalIssuer != nil && r.URL.Path == adminrenewal.ConfirmPath:
			var request adminrenewal.ConfirmRequest
			if wire.Decode(body, &request) != nil || request.Version != adminrenewal.Version {
				deny()
				return
			}
			var id string
			id, e = p.store.FinishAdminRenewal(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.ChallengeID, request.Response)
			if e == nil {
				e = p.store.IssueAdminRenewal(r.Context(), c.AdministratorTrust.IssuerID(), id, c.AdministratorTrust, c.AdministratorRenewalIssuer)
			}
			if e == nil {
				var der []byte
				der, e = p.store.AdminRenewalCertificate(r.Context(), conn, c.AdministratorTrust, id)
				result = adminrenewal.Certificate{Version: adminrenewal.Version, RenewalID: id, CertificateDER: der}
			}
		case c.Profile == pki.Administrator && r.URL.Path == adminrenewal.CertificatePath:
			var request adminrenewal.CertificateRequest
			if wire.Decode(body, &request) != nil || request.Version != adminrenewal.Version {
				deny()
				return
			}
			var der []byte
			der, e = p.store.AdminRenewalCertificate(r.Context(), conn, c.AdministratorTrust, request.RenewalID)
			result = adminrenewal.Certificate{Version: adminrenewal.Version, RenewalID: request.RenewalID, CertificateDER: der}
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
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/dashboard/access":
			var request AccessInspectionRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.InspectAccess(r.Context(), conn, c.AdministratorTrust, request)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/factors/challenge":
			var request FactorRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.store.BeginFactor(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/factors/confirm":
			var request finishApprovalRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.store.FinishFactor(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.ID, request.Response)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/invitations/challenge":
			var request InvitationRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.store.BeginInvitation(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request)
		case c.Profile == pki.Administrator && r.URL.Path == "/api/v1/admin/invitations/confirm":
			var request finishApprovalRequest
			if wire.Decode(body, &request) != nil {
				deny()
				return
			}
			result, e = p.store.FinishInvitation(r.Context(), conn, c.AdministratorTrust, c.AdministratorVerifier, request.ID, request.Response)
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
