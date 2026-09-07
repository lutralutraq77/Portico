// Package issuer implements the controller side of the restricted step-ca
// service. The controller holds a provisioner key, never an issuer signing key.
package issuer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"portico.local/portico/internal/pki"
)

var ErrRejected = errors.New("issuer request rejected")

const SignPath = "/1.0/sign"
const MaxBody = 32 * 1024

// Approval is signed by the registration authority. It is never supplied by an
// enrolling client. Exact CSR binding includes its proof-of-possession signature.
type Approval struct {
	DeploymentID string      `json:"deployment"`
	IssuerID     string      `json:"issuer"`
	PrincipalID  string      `json:"principal"`
	Profile      pki.Profile `json:"profile"`
	NotBefore    time.Time   `json:"notBefore"`
	NotAfter     time.Time   `json:"notAfter"`
}
type Claims struct {
	jwt.Claims
	SANs         []string `json:"sans"`
	Confirmation struct {
		Fingerprint string `json:"x5rt#S256"`
	} `json:"cnf"`
	Approval Approval `json:"portico"`
}
type SignRequest struct {
	CSR   string `json:"csr"`
	Token string `json:"ott"`
}
type SignResponse struct {
	Certificate string `json:"crt"`
}

type Config struct {
	Endpoint, Provisioner, KeyID string
	ProvisionerKey               *ecdsa.PrivateKey
	ServerRootDER                []byte
	ServerSPKI                   string
	ControllerIdentity           tls.Certificate
	Trust                        *pki.Trust
}
type Client struct {
	endpoint, provisioner, keyID string
	signer                       jose.Signer
	trust                        *pki.Trust
	http                         *http.Client
}

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.Trust == nil || c.Provisioner == "" || c.KeyID == "" || len(c.ServerSPKI) != 64 || len(c.ControllerIdentity.Certificate) == 0 || c.ControllerIdentity.PrivateKey == nil || c.ProvisionerKey == nil || c.ProvisionerKey.Curve != elliptic.P256() {
		return nil, ErrRejected
	}
	root, e := x509.ParseCertificate(c.ServerRootDER)
	if e != nil || !root.IsCA {
		return nil, ErrRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	keyDER, e := x509.MarshalPKCS8PrivateKey(c.ProvisionerKey)
	if e != nil {
		return nil, ErrRejected
	}
	key, e := x509.ParsePKCS8PrivateKey(keyDER)
	if e != nil {
		return nil, ErrRejected
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", c.KeyID))
	if e != nil {
		return nil, ErrRejected
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{c.ControllerIdentity}, ServerName: u.Hostname(), SessionTicketsDisabled: true}
	tlsConfig.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 || pki.Hash(s.PeerCertificates[0].RawSubjectPublicKeyInfo) != c.ServerSPKI {
			return ErrRejected
		}
		return nil
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}
	return &Client{c.Endpoint + SignPath, c.Provisioner, c.KeyID, signer, c.Trust, client}, nil
}

func (c *Client) Issue(ctx context.Context, r pki.IssuanceRequest) ([]byte, error) {
	csr, e := pki.ParseCSR(r.CSR)
	if e != nil || r.DeploymentID != c.trust.DeploymentID() || r.IssuerID != c.trust.IssuerID() || r.Profile != c.trust.Profile() || !pki.ValidID(r.AttemptID) {
		return nil, ErrRejected
	}
	sans, e := pki.IdentitySANs(r.DeploymentID, r.Profile, r.PrincipalID)
	if e != nil {
		return nil, ErrRejected
	}
	now := time.Now().UTC()
	claims := Claims{Claims: jwt.Claims{Issuer: c.provisioner, Subject: r.PrincipalID, Audience: jwt.Audience{c.endpoint}, ID: r.AttemptID, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}, SANs: sans, Approval: Approval{r.DeploymentID, r.IssuerID, r.PrincipalID, r.Profile, r.NotBefore, r.NotAfter}}
	sum := sha256.Sum256(csr.Raw)
	claims.Confirmation.Fingerprint = base64.RawURLEncoding.EncodeToString(sum[:])
	if claims.ValidateApproval(c.trust, now) != nil {
		return nil, ErrRejected
	}
	token, e := jwt.Signed(c.signer).Claims(claims).Serialize()
	if e != nil {
		return nil, ErrRejected
	}
	body, e := json.Marshal(SignRequest{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})), token})
	if e != nil {
		return nil, ErrRejected
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if e != nil {
		return nil, ErrRejected
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return nil, ErrRejected
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if e != nil || len(b) > MaxBody {
		return nil, ErrRejected
	}
	var result SignResponse
	if Decode(b, &result) != nil {
		return nil, ErrRejected
	}
	block, rest := pem.Decode([]byte(result.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrRejected
	}
	cred, e := c.trust.Verify(block.Bytes, r.PrincipalID, now)
	if e != nil || cred.SPKISHA256 != pki.Hash(csr.RawSubjectPublicKeyInfo) || !cred.NotBefore.Equal(r.NotBefore) || !cred.NotAfter.Equal(r.NotAfter) {
		return nil, ErrRejected
	}
	return bytes.Clone(block.Bytes), nil
}

// ValidateApproval is policy validation after signature verification, never a
// substitute for it. The restricted service also verifies issuer and audience.
func (c Claims) ValidateApproval(trust *pki.Trust, now time.Time) error {
	a := c.Approval
	sans, e := pki.IdentitySANs(a.DeploymentID, a.Profile, a.PrincipalID)
	if e != nil || trust == nil || a.DeploymentID != trust.DeploymentID() || a.IssuerID != trust.IssuerID() || a.Profile != trust.Profile() || !pki.ValidID(c.ID) || c.Subject != a.PrincipalID || !slices.Equal(c.SANs, sans) || len(c.Confirmation.Fingerprint) != 43 || c.IssuedAt == nil || c.NotBefore == nil || c.Expiry == nil {
		return ErrRejected
	}
	if c.IssuedAt.Time().After(now) || now.Sub(c.IssuedAt.Time()) > time.Minute || c.Expiry.Time().Sub(c.IssuedAt.Time()) != time.Minute || c.NotBefore.Time() != c.IssuedAt.Time() || !now.Before(c.Expiry.Time()) {
		return ErrRejected
	}
	if a.NotBefore.After(now) || now.Sub(a.NotBefore) > time.Hour || !a.NotBefore.Equal(a.NotBefore.Truncate(time.Second)) || !a.NotAfter.Equal(a.NotAfter.Truncate(time.Second)) || !a.NotAfter.After(now) || a.NotAfter.Sub(a.NotBefore) > 24*time.Hour || a.NotAfter.After(trust.NotAfter()) {
		return ErrRejected
	}
	return nil
}

// Decode rejects extra fields, trailing values and oversized messages.
func Decode(b []byte, v any) error {
	if len(b) == 0 || len(b) > MaxBody {
		return ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrRejected
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrRejected
	}
	return nil
}
