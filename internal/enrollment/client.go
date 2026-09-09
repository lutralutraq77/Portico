package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

// Endpoints/trust and the expected principal/deadline come from the approved
// invitation bundle through a trusted channel, never from discovery or TOFU.
type Endpoint struct {
	URL           string
	ServerRootDER []byte
	ServerSPKI    string
}
type Config struct {
	Redemption, Activation Endpoint
	Trust                  *pki.Trust
	PrincipalID            string
	NotAfter               time.Time
	Timeout                time.Duration
	MaxRequests            int
}
type Client struct {
	config Config
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	work   sync.WaitGroup
	slots  chan struct{}
}

func New(c Config) (*Client, error) {
	if c.Trust == nil || (c.Trust.Profile() != pki.Device && c.Trust.Profile() != pki.Connector) || !pki.ValidID(c.PrincipalID) || !c.NotAfter.After(time.Now()) || !c.NotAfter.Equal(c.NotAfter.Truncate(time.Second)) || c.NotAfter.After(c.Trust.NotAfter()) || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.MaxRequests < 1 || c.MaxRequests > 8 || c.Redemption.URL == c.Activation.URL {
		return nil, ErrRejected
	}
	for _, e := range []Endpoint{c.Redemption, c.Activation} {
		if _, err := endpointTLS(e, nil); err != nil {
			return nil, ErrRejected
		}
	}
	c.Redemption.ServerRootDER = bytes.Clone(c.Redemption.ServerRootDER)
	c.Activation.ServerRootDER = bytes.Clone(c.Activation.ServerRootDER)
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{config: c, ctx: ctx, cancel: cancel, slots: make(chan struct{}, c.MaxRequests)}, nil
}

func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.work.Wait()
}

// Each call uses a new TLS connection; activation cannot reuse anonymous TLS.
// No redirects, environment proxy, compressed response or automatic replay.
func endpointTLS(e Endpoint, identity *tls.Certificate) (*tls.Config, error) {
	u, err := url.Parse(e.URL)
	pin, pinErr := hex.DecodeString(e.ServerSPKI)
	if err != nil || !identityfile.LoopbackEndpoint(e.URL) || u.Host != strings.ToLower(u.Host) || pinErr != nil || len(pin) != 32 || len(e.ServerRootDER) > pki.MaxDER {
		return nil, ErrRejected
	}
	_, port, err := net.SplitHostPort(u.Host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return nil, ErrRejected
	}
	root, err := x509.ParseCertificate(e.ServerRootDER)
	if err != nil || !root.IsCA {
		return nil, ErrRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), SessionTicketsDisabled: true}
	if identity != nil {
		tc.Certificates = []tls.Certificate{*identity}
	}
	tc.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 3 || pki.Hash(s.PeerCertificates[0].RawSubjectPublicKeyInfo) != strings.ToLower(e.ServerSPKI) {
			return ErrRejected
		}
		return nil
	}
	return tc, nil
}

func (c *Client) post(ctx context.Context, endpoint Endpoint, identity *tls.Certificate, path string, request, result any) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrRejected
	}
	select {
	case c.slots <- struct{}{}:
	default:
		c.mu.Unlock()
		return ErrRejected
	}
	c.work.Add(1)
	c.mu.Unlock()
	defer func() { <-c.slots; c.work.Done() }()
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	data, err := json.Marshal(request)
	if err != nil || len(data) > MaxBody {
		return ErrRejected
	}
	defer clear(data)
	tc, err := endpointTLS(endpoint, identity)
	if err != nil {
		return ErrRejected
	}
	transport := &http.Transport{TLSClientConfig: tc, Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 1, TLSHandshakeTimeout: c.config.Timeout, ResponseHeaderTimeout: c.config.Timeout, MaxResponseHeaderBytes: 8192, DialContext: (&net.Dialer{Timeout: c.config.Timeout}).DialContext}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL+path, bytes.NewReader(data))
	if err != nil {
		return ErrRejected
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(r)
	if err != nil {
		return ErrRejected
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || response.ContentLength > MaxBody {
		return ErrRejected
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody || wire.Decode(body, result) != nil || ctx.Err() != nil || c.ctx.Err() != nil {
		return ErrRejected
	}
	return nil
}

// Redeem may return the same public certificate after an identical retry. A
// failed/uncertain request never authorizes another signer invocation or key.
func (c *Client) Redeem(ctx context.Context, request RedeemRequest, key crypto.Signer) (tls.Certificate, error) {
	if c == nil || key == nil || !request.Valid() {
		return tls.Certificate{}, ErrRejected
	}
	csr, err := pki.ParseCSR(request.CSR)
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(public, csr.RawSubjectPublicKeyInfo) {
		return tls.Certificate{}, ErrRejected
	}
	var response CertificateResponse
	if c.post(ctx, c.config.Redemption, nil, RedeemPath, request, &response) != nil || response.Version != Version || response.InvitationID != request.InvitationID || response.AttemptID != request.AttemptID {
		return tls.Certificate{}, ErrRejected
	}
	credential, err := c.config.Trust.Verify(response.CertificateDER, c.config.PrincipalID, time.Now())
	if err != nil || !credential.NotAfter.Equal(c.config.NotAfter) || credential.SPKISHA256 != pki.Hash(public) {
		return tls.Certificate{}, ErrRejected
	}
	identity, err := c.config.Trust.TLSIdentity(tls.Certificate{Certificate: [][]byte{response.CertificateDER}, PrivateKey: key})
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	return identity, nil
}

func (c *Client) Activate(ctx context.Context, id string, identity tls.Certificate) error {
	if c == nil || !pki.ValidID(id) {
		return ErrRejected
	}
	identity, err := c.config.Trust.TLSIdentity(identity)
	if err != nil {
		return ErrRejected
	}
	credential, err := c.config.Trust.Verify(identity.Certificate[0], c.config.PrincipalID, time.Now())
	if err != nil || !credential.NotAfter.Equal(c.config.NotAfter) {
		return ErrRejected
	}
	var result Activated
	if c.post(ctx, c.config.Activation, &identity, ActivatePath, ActivateRequest{Version: Version, InvitationID: id}, &result) != nil || result.Version != Version || result.InvitationID != id {
		return ErrRejected
	}
	return nil
}
