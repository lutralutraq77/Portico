// Package adminbridge provides the native, fixed-origin administration transport.
// The device signer remains in native code; the browser receives only responses.
package adminbridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

var ErrRejected = errors.New("administrator transport rejected")

const MaxResponse = 256 * 1024

const browserCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"

type Config struct {
	Origin, ServerSPKI string
	ServerRootDER      []byte
	AdministratorTrust *pki.Trust
	Identity           tls.Certificate
	// BootstrapAddress must be a literal loopback address. Socket instead names
	// an already-authorized protected local stream. Neither is browser-selected.
	BootstrapAddress  string
	Socket            string
	Timeout, Lifetime time.Duration
}

// Request deliberately has no arbitrary headers, proxy destination, cookies,
// authentication token, redirect target or signing operation.
type Request struct {
	Method, Path, Origin, Site string
	Body                       []byte
}

type Response struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

type Client struct {
	origin, host string
	trust        *pki.Trust
	leaf         []byte
	timeout      time.Duration
	client       *http.Client
	transport    *http.Transport
	context      context.Context
	cancel       context.CancelFunc
	admission    chan struct{}
}

func Origin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != value || strings.ContainsAny(u.Host, "%\\\x00\r\n") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	host := u.Hostname()
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && address.String() == host
	}
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, ":[]") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	// WHATWG URLs interpret numeric final labels as legacy IPv4 spellings.
	// Only canonical IP literals (handled above) may take that path.
	last := host[strings.LastIndex(host, ".")+1:]
	_, numeric := strconv.ParseUint(last, 0, 64)
	if numeric == nil || strings.Trim(last, "0123456789") == "" {
		return false
	}
	return true
}

func New(parent context.Context, c Config) (*Client, error) {
	if parent == nil || parent.Err() != nil || !Origin(c.Origin) || c.AdministratorTrust == nil || c.AdministratorTrust.Profile() != pki.Administrator || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.Lifetime <= 0 || c.Lifetime > 10*time.Minute || (c.BootstrapAddress == "") == (c.Socket == "") {
		return nil, ErrRejected
	}
	pin, err := hex.DecodeString(c.ServerSPKI)
	if err != nil || len(pin) != 32 || hex.EncodeToString(pin) != c.ServerSPKI || len(c.ServerRootDER) == 0 || len(c.ServerRootDER) > pki.MaxDER {
		return nil, ErrRejected
	}
	root, err := x509.ParseCertificate(c.ServerRootDER)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid {
		return nil, ErrRejected
	}
	identity, err := c.AdministratorTrust.TLSIdentity(c.Identity)
	if err != nil {
		return nil, ErrRejected
	}
	credential, err := c.AdministratorTrust.VerifyPeer(identity.Certificate[0], time.Now())
	if err != nil {
		return nil, ErrRejected
	}
	var dial func(context.Context, string, string) (net.Conn, error)
	if c.BootstrapAddress != "" {
		address, err := netip.ParseAddrPort(c.BootstrapAddress)
		if err != nil || !address.Addr().IsLoopback() || address.Addr().Is4In6() || address.Addr().Zone() != "" || address.Port() == 0 || address.String() != c.BootstrapAddress {
			return nil, ErrRejected
		}
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: c.Timeout}).DialContext(ctx, "tcp", address.String())
		}
	} else {
		if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || len(c.Socket) > 4096 || strings.ContainsRune(c.Socket, 0) {
			return nil, ErrRejected
		}
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) { return localipc.Dial(ctx, c.Socket) }
	}
	u, _ := url.Parse(c.Origin)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), Certificates: []tls.Certificate{identity}, SessionTicketsDisabled: true}
	tc.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 || pki.Hash(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != c.ServerSPKI {
			return ErrRejected
		}
		return nil
	}
	// Each request proves the device key again. With no reused connection or
	// idempotency headers, the transport cannot retry a sensitive POST.
	transport := &http.Transport{TLSClientConfig: tc, Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 4, TLSHandshakeTimeout: c.Timeout, ResponseHeaderTimeout: c.Timeout, MaxResponseHeaderBytes: 8192, DialContext: dial}
	end := time.Now().Add(c.Lifetime)
	if credential.NotAfter.Before(end) {
		end = credential.NotAfter
	}
	ctx, cancel := context.WithDeadline(parent, end)
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{origin: c.Origin, host: u.Host, trust: c.AdministratorTrust, leaf: bytes.Clone(identity.Certificate[0]), timeout: c.Timeout, client: client, transport: transport, context: ctx, cancel: cancel, admission: make(chan struct{}, 4)}, nil
}

func (c *Client) Close()                { c.cancel(); c.transport.CloseIdleConnections() }
func (c *Client) Origin() string        { return c.origin }
func (c *Client) Done() <-chan struct{} { return c.context.Done() }

func (c *Client) permitted(r Request) bool {
	if r.Site != "" && r.Site != "none" && r.Site != "same-origin" {
		return false
	}
	if r.Method == http.MethodGet {
		return (r.Origin == "" || r.Origin == c.origin) && len(r.Body) == 0 && (r.Path == "/admin" || r.Path == "/admin.js" || r.Path == "/admin.css")
	}
	if r.Method != http.MethodPost || r.Origin != c.origin || len(r.Body) == 0 || len(r.Body) > wire.MaxBody {
		return false
	}
	switch r.Path {
	case "/api/v1/admin/dashboard/inventory", "/api/v1/admin/dashboard/access", "/api/v1/admin/factors/challenge", "/api/v1/admin/factors/confirm", "/api/v1/admin/invitations/challenge", "/api/v1/admin/invitations/confirm", "/api/v1/admin/policy/preview", "/api/v1/admin/policy/challenge", "/api/v1/admin/policy/confirm":
		var fields map[string]json.RawMessage
		return wire.Decode(r.Body, &fields) == nil && fields != nil
	default:
		return false
	}
}

// Exchange accepts only requests from the dedicated native browser pipe. Live
// administrator status and fresh hardware approval remain server decisions.
func (c *Client) Exchange(parent context.Context, request Request) (Response, error) {
	if c == nil || parent == nil || parent.Err() != nil || c.context.Err() != nil || !c.permitted(request) {
		return Response{}, ErrRejected
	}
	select {
	case c.admission <- struct{}{}:
	default:
		return Response{}, ErrRejected
	}
	defer func() { <-c.admission }()
	if _, err := c.trust.VerifyPeer(c.leaf, time.Now()); err != nil {
		c.Close()
		return Response{}, ErrRejected
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	stop := context.AfterFunc(c.context, cancel)
	defer stop()
	r, err := http.NewRequestWithContext(ctx, request.Method, c.origin+request.Path, bytes.NewReader(bytes.Clone(request.Body)))
	if err != nil {
		return Response{}, ErrRejected
	}
	r.Host = c.host
	if request.Method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	if request.Origin != "" {
		r.Header.Set("Origin", request.Origin)
	}
	if request.Site != "" {
		r.Header.Set("Sec-Fetch-Site", request.Site)
	}
	response, err := c.client.Do(r)
	if err != nil {
		return Response{}, ErrRejected
	}
	defer response.Body.Close()
	if (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusForbidden) || response.ContentLength > MaxResponse || response.Header.Get("Content-Encoding") != "" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Location") != "" || response.Header.Get("Content-Disposition") != "" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		return Response{}, ErrRejected
	}
	contentType := response.Header.Get("Content-Type")
	for _, name := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options"} {
		if len(response.Header.Values(name)) != 1 {
			return Response{}, ErrRejected
		}
	}
	want := "application/json"
	if request.Method == http.MethodGet && response.StatusCode == http.StatusOK {
		switch request.Path {
		case "/admin":
			want = "text/html; charset=utf-8"
		case "/admin.css":
			want = "text/css; charset=utf-8"
		case "/admin.js":
			want = "text/javascript; charset=utf-8"
		}
	}
	if contentType != want {
		return Response{}, ErrRejected
	}
	limit := int64(MaxResponse)
	if want == "application/json" {
		limit = wire.MaxBody
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit || ctx.Err() != nil || c.context.Err() != nil {
		return Response{}, ErrRejected
	}
	headers := map[string]string{"Content-Type": contentType, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
	for _, name := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Frame-Options"} {
		values := response.Header.Values(name)
		if len(values) != 1 || values[0] == "" {
			return Response{}, ErrRejected
		}
		headers[name] = values[0]
	}
	if headers["Referrer-Policy"] != "no-referrer" || headers["X-Frame-Options"] != "DENY" || (headers["Content-Security-Policy"] != browserCSP && headers["Content-Security-Policy"] != "default-src 'none'") {
		clear(body)
		return Response{}, ErrRejected
	}
	return Response{Status: response.StatusCode, Headers: headers, Body: body}, nil
}
