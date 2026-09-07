package control

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
	"net/url"
	"strconv"
	"strings"
	"time"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

var ErrRejected = errors.New("control request rejected")

type ClientConfig struct {
	Endpoint       string
	ServerRootDER  []byte
	ServerSPKI     string
	Identity       tls.Certificate
	Profile        pki.Profile
	Timeout        time.Duration
	MaxConnections int
}
type Client struct {
	endpoint  string
	profile   pki.Profile
	timeout   time.Duration
	client    *http.Client
	transport *http.Transport
	closed    context.Context
	cancel    context.CancelFunc
}

func NewClient(c ClientConfig) (*Client, error) {
	u, e := url.Parse(c.Endpoint)
	pin, pinError := hex.DecodeString(c.ServerSPKI)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(c.ServerRootDER) > pki.MaxDER || pinError != nil || len(pin) != 32 || (c.Profile != pki.Device && c.Profile != pki.Connector) || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.MaxConnections < 1 || c.MaxConnections > 32 || len(c.Identity.Certificate) == 0 || len(c.Identity.Certificate) > 3 || c.Identity.PrivateKey == nil {
		return nil, ErrRejected
	}
	host, port, e := net.SplitHostPort(u.Host)
	n, portError := strconv.Atoi(port)
	if e != nil || host == "" || portError != nil || n < 1 || n > 65535 {
		return nil, ErrRejected
	}
	root, e := x509.ParseCertificate(c.ServerRootDER)
	if e != nil || !root.IsCA {
		return nil, ErrRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	identity := tls.Certificate{PrivateKey: c.Identity.PrivateKey}
	for _, der := range c.Identity.Certificate {
		if len(der) == 0 || len(der) > pki.MaxDER {
			return nil, ErrRejected
		}
		identity.Certificate = append(identity.Certificate, bytes.Clone(der))
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host, Certificates: []tls.Certificate{identity}, SessionTicketsDisabled: true}
	tc.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 3 || pki.Hash(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != strings.ToLower(c.ServerSPKI) {
			return ErrRejected
		}
		return nil
	}
	transport := &http.Transport{TLSClientConfig: tc, Proxy: nil, DisableCompression: true, MaxConnsPerHost: c.MaxConnections, MaxIdleConns: c.MaxConnections, MaxIdleConnsPerHost: c.MaxConnections, IdleConnTimeout: 15 * time.Second, TLSHandshakeTimeout: c.Timeout, ResponseHeaderTimeout: c.Timeout, MaxResponseHeaderBytes: 8192, DialContext: (&net.Dialer{Timeout: c.Timeout}).DialContext}
	closed, cancel := context.WithCancel(context.Background())
	return &Client{endpoint: c.Endpoint, profile: c.Profile, timeout: c.Timeout, transport: transport, closed: closed, cancel: cancel, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() { c.cancel(); c.transport.CloseIdleConnections() }

func (c *Client) post(ctx context.Context, profile pki.Profile, path string, request, result any) error {
	if c.profile != profile || c.closed.Err() != nil {
		return ErrRejected
	}
	data, e := json.Marshal(request)
	if e != nil || len(data) > wire.MaxBody {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	stop := context.AfterFunc(c.closed, cancel)
	defer stop()
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(data))
	if e != nil {
		return ErrRejected
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := c.client.Do(r)
	if e != nil {
		return ErrRejected
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || response.ContentLength > wire.MaxBody {
		return ErrRejected
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, wire.MaxBody+1))
	if e != nil || wire.Decode(body, result) != nil || ctx.Err() != nil || c.closed.Err() != nil {
		return ErrRejected
	}
	return nil
}

func (c *Client) CheckConnector(ctx context.Context, r ConnectorCheck) (ConnectorStatus, error) {
	var v ConnectorStatus
	e := c.post(ctx, pki.Device, "/api/v1/device/check-connector", r, &v)
	if e != nil || v.Version != Version || !validResource(v.Resource) || !pki.ValidID(v.ConnectorCertificateID) || v.PolicyRevision < 1 || v.CheckedAt.IsZero() || !v.Resource.Until.After(v.CheckedAt) || v.Resource.ID != r.ResourceID || v.Resource.Revision != r.Revision {
		return ConnectorStatus{}, ErrRejected
	}
	return v, nil
}
func (c *Client) Hosting(ctx context.Context) (HostingSnapshot, error) {
	var v HostingSnapshot
	e := c.post(ctx, pki.Connector, "/api/v1/connector/hosting", struct{}{}, &v)
	if e != nil || !validHosting(v) {
		return HostingSnapshot{}, ErrRejected
	}
	return v, nil
}
func (c *Client) Authorize(ctx context.Context, r AuthorizeRequest) (Authorization, error) {
	var v Authorization
	e := c.post(ctx, pki.Connector, "/api/v1/connector/authorize", r, &v)
	if e != nil || !validAuthorization(v) || v.Sequence != 1 || v.Resource.ID != r.ResourceID || v.Resource.Revision != r.Revision {
		return Authorization{}, ErrRejected
	}
	return v, nil
}
func (c *Client) session(ctx context.Context, path string, r SessionRequest) (Authorization, error) {
	var v Authorization
	e := c.post(ctx, pki.Connector, path, r, &v)
	if e != nil || !validAuthorization(v) || v.SessionID != r.SessionID || r.Sequence < 1 || v.Sequence <= r.Sequence || v.Sequence-r.Sequence != 1 {
		return Authorization{}, ErrRejected
	}
	return v, nil
}
func (c *Client) Activate(ctx context.Context, r SessionRequest) (Authorization, error) {
	return c.session(ctx, "/api/v1/connector/activate", r)
}
func (c *Client) Renew(ctx context.Context, r SessionRequest) (Authorization, error) {
	return c.session(ctx, "/api/v1/connector/renew", r)
}
func (c *Client) CloseSession(ctx context.Context, r SessionRequest) error {
	return c.post(ctx, pki.Connector, "/api/v1/connector/close", r, &struct{}{})
}
func (c *Client) Cancellations(ctx context.Context, r CancellationRequest) (CancellationBatch, error) {
	if !r.Valid() {
		return CancellationBatch{}, ErrRejected
	}
	var v CancellationBatch
	e := c.post(ctx, pki.Connector, "/api/v1/connector/cancellations", r, &v)
	if e != nil || !validCancellations(v, r) {
		return CancellationBatch{}, ErrRejected
	}
	return v, nil
}
func (c *Client) AcknowledgeCancellation(ctx context.Context, r CancellationAck) error {
	return c.post(ctx, pki.Connector, "/api/v1/connector/acknowledge-cancellation", r, &struct{}{})
}
