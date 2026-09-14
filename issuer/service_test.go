package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"portico.local/portico/internal/controller"
	"portico.local/portico/internal/issuer"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type lab struct {
	s       *Service
	config  Config
	client  *issuer.Client
	http    *http.Client
	request controller.IssuanceRequest
	key     *ecdsa.PrivateKey
	ra      tls.Certificate
	otherRA tls.Certificate
	trust   *pki.Trust
}

func newLab(t *testing.T, profile pki.Profile) *lab {
	t.Helper()
	root, rk := testfixture.Root(t)
	ik := testfixture.Key(t)
	i := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	tc := pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: profile, RootDER: root.Raw, IssuerDER: i.Raw}
	trust, e := pki.NewTrust(tc)
	testfixture.Must(t, e)
	cr, ck := testfixture.Root(t)
	server, ra := testfixture.TLSIdentity(t, cr, ck, true), testfixture.TLSIdentity(t, cr, ck, false)
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	testfixture.Must(t, e)
	endpoint := "https://localhost:" + strings.Split(l.Addr().String(), ":")[1]
	pk := testfixture.Key(t)
	public := jose.JSONWebKey{Key: &pk.PublicKey, KeyID: uuid.NewString(), Algorithm: "ES256", Use: "sig"}
	cfg := Config{Endpoint: endpoint, Provisioner: "portico-registration-authority", KeyID: public.KeyID, DatabasePath: filepath.Join(t.TempDir(), "issuer.db"), TrustConfig: tc, IssuerSigner: ik, ProvisionerPublicKey: public, ServerIdentity: server, ControllerRootDER: cr.Raw, ControllerSPKI: pki.Hash(ra.Leaf.RawSubjectPublicKeyInfo)}
	s, e := New(cfg)
	testfixture.Must(t, e)
	go func() { _ = s.Serve(l) }()
	client, e := issuer.New(issuer.Config{Endpoint: endpoint, Provisioner: cfg.Provisioner, KeyID: cfg.KeyID, ProvisionerKey: pk, ServerRootDER: cr.Raw, ServerSPKI: pki.Hash(server.Leaf.RawSubjectPublicKeyInfo), ControllerIdentity: ra, Trust: trust})
	testfixture.Must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(cr)
	h := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{ra}}, DisableKeepAlives: true}, Timeout: 5 * time.Second}
	deviceKey := testfixture.Key(t)
	csr, e := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, deviceKey)
	testfixture.Must(t, e)
	r := controller.IssuanceRequest{AttemptID: uuid.NewString(), DeploymentID: tc.DeploymentID, IssuerID: tc.IssuerID, PrincipalID: uuid.NewString(), Profile: profile, CSR: csr, NotBefore: time.Now().UTC().Truncate(time.Second), NotAfter: time.Now().UTC().Truncate(time.Second).Add(time.Hour)}
	lab := &lab{s: s, config: cfg, client: client, http: h, request: r, key: pk, ra: ra, otherRA: testfixture.TLSIdentity(t, cr, ck, false), trust: trust}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lab.s.Close(ctx)
		h.CloseIdleConnections()
	})
	return lab
}
func (l *lab) token(t *testing.T, change func(*issuer.Claims)) string {
	t.Helper()
	r := l.request
	now := time.Now().UTC()
	sans, e := pki.IdentitySANs(r.DeploymentID, r.Profile, r.PrincipalID)
	testfixture.Must(t, e)
	c := issuer.Claims{Claims: jwt.Claims{Issuer: l.config.Provisioner, Subject: r.PrincipalID, Audience: jwt.Audience{l.config.Endpoint + issuer.SignPath}, ID: uuid.NewString(), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}, SANs: sans, Approval: issuer.Approval{DeploymentID: r.DeploymentID, IssuerID: r.IssuerID, PrincipalID: r.PrincipalID, Profile: r.Profile, NotBefore: r.NotBefore, NotAfter: r.NotAfter}}
	h := sha256.Sum256(r.CSR)
	c.Confirmation.Fingerprint = base64.RawURLEncoding.EncodeToString(h[:])
	if change != nil {
		change(&c)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: l.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", l.config.KeyID))
	testfixture.Must(t, e)
	token, e := jwt.Signed(signer).Claims(c).Serialize()
	testfixture.Must(t, e)
	return token
}
func (l *lab) send(t *testing.T, path string, body any, client *http.Client) int {
	t.Helper()
	b, e := json.Marshal(body)
	testfixture.Must(t, e)
	r, e := http.NewRequest(http.MethodPost, l.config.Endpoint+path, bytes.NewReader(b))
	testfixture.Must(t, e)
	r.Header.Set("Content-Type", "application/json")
	res, e := client.Do(r)
	if e != nil {
		return 0
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}
func TestRealStepCAProfilesAndEndpointRestrictions(t *testing.T) {
	for _, profile := range []pki.Profile{pki.Device, pki.Connector, pki.Administrator} {
		t.Run(string(profile), func(t *testing.T) {
			l := newLab(t, profile)
			der, e := l.client.Issue(context.Background(), l.request)
			testfixture.Must(t, e)
			c, e := l.trust.Verify(der, l.request.PrincipalID, time.Now())
			testfixture.Must(t, e)
			if c.Profile != profile {
				t.Fatal("wrong profile")
			}
			receipt, e := l.s.Result(l.request.AttemptID)
			testfixture.Must(t, e)
			if !bytes.Equal(receipt.Certificate, der) || receipt.CSRHash != pki.Hash(l.request.CSR) {
				t.Fatal("receipt changed issued result")
			}
			if _, e = l.client.Issue(context.Background(), l.request); e == nil {
				t.Fatal("attempt replay signed again")
			}
			for _, path := range []string{"/renew", "/rekey", "/1.0/renew", "/1.0/rekey", "/ssh/sign", "/acme/new-order", "/1.0/sign/"} {
				if status := l.send(t, path, map[string]string{}, l.http); status != 403 {
					t.Fatalf("alternate endpoint %s: %d", path, status)
				}
			}
		})
	}
}
func TestRealStepCARejectsBypassAndPersistsReplay(t *testing.T) {
	l := newLab(t, pki.Device)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: l.request.CSR}))
	for _, name := range []string{"missing", "profile", "identity", "deadline", "expired", "audience", "wrong_csr", "template_override", "not_after_override"} {
		t.Run(name, func(t *testing.T) {
			token := l.token(t, func(c *issuer.Claims) {
				switch name {
				case "profile":
					c.Approval.Profile = pki.Administrator
				case "identity":
					c.Approval.PrincipalID = uuid.NewString()
				case "deadline":
					c.Approval.NotAfter = c.Approval.NotBefore.Add(48 * time.Hour)
				case "expired":
					c.IssuedAt = jwt.NewNumericDate(time.Now().Add(-3 * time.Minute))
					c.NotBefore = c.IssuedAt
					c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
				case "audience":
					c.Audience = jwt.Audience{"https://elsewhere.test/1.0/sign"}
				}
			})
			body := map[string]any{"csr": csr, "ott": token}
			switch name {
			case "missing":
				body["ott"] = ""
			case "wrong_csr":
				b, e := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, testfixture.Key(t))
				testfixture.Must(t, e)
				body["csr"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}))
			case "template_override":
				body["templateData"] = map[string]any{"isCA": true}
			case "not_after_override":
				body["notAfter"] = time.Now().Add(24 * time.Hour)
			}
			if status := l.send(t, issuer.SignPath, body, l.http); status != 403 {
				t.Fatalf("bypass accepted: %d", status)
			}
		})
	}
	token := l.token(t, nil)
	body := issuer.SignRequest{CSR: csr, Token: token}
	if status := l.send(t, issuer.SignPath, body, l.http); status != 201 {
		t.Fatalf("authorized sign failed: %d", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testfixture.Must(t, l.s.Close(ctx))
	listener, e := net.Listen("tcp4", strings.Replace(strings.TrimPrefix(l.config.Endpoint, "https://"), "localhost", "127.0.0.1", 1))
	testfixture.Must(t, e)
	l.s, e = New(l.config)
	testfixture.Must(t, e)
	go func() { _ = l.s.Serve(listener) }()
	if status := l.send(t, issuer.SignPath, body, l.http); status != 403 {
		t.Fatal("restart lost consumed token")
	}
	transport := l.http.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = nil
	noCert := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer noCert.CloseIdleConnections()
	if status := l.send(t, issuer.SignPath, issuer.SignRequest{CSR: csr, Token: l.token(t, nil)}, noCert); status != 0 {
		t.Fatal("issuer accepted missing controller certificate")
	}
	otherRoot, otherKey := testfixture.Root(t)
	transport = transport.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{testfixture.TLSIdentity(t, otherRoot, otherKey, false)}
	wrongCert := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer wrongCert.CloseIdleConnections()
	if status := l.send(t, issuer.SignPath, issuer.SignRequest{CSR: csr, Token: l.token(t, nil)}, wrongCert); status != 0 {
		t.Fatal("issuer accepted wrong controller certificate")
	}
	transport = transport.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{l.otherRA}
	wrongPin := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer wrongPin.CloseIdleConnections()
	if status := l.send(t, issuer.SignPath, issuer.SignRequest{CSR: csr, Token: l.token(t, nil)}, wrongPin); status != 0 {
		t.Fatal("issuer accepted a valid unpinned controller key")
	}
	stored, e := l.s.database.List([]byte("used_ott"))
	testfixture.Must(t, e)
	for _, entry := range stored {
		if bytes.Contains(entry.Value, []byte(token)) || len(entry.Value) != 64 {
			t.Fatal("issuer persisted plaintext provisioning token")
		}
	}
}

func TestControllerEnrollmentThroughRealIssuer(t *testing.T) {
	l := newLab(t, pki.Device)
	ctx := context.Background()
	s, e := controller.Open(ctx, t.TempDir())
	testfixture.Must(t, e)
	defer func() { _ = s.Close() }()
	actor, user := uuid.NewString(), uuid.NewString()
	testfixture.Must(t, s.Update(ctx, actor, func(tx *controller.Tx) error {
		if e := tx.AddUser(controller.User{ID: user, Name: "Isolated issuer integration", Enabled: true}); e != nil {
			return e
		}
		if e := tx.AddDevice(controller.Device{ID: l.request.PrincipalID, UserID: user, Name: "Fixture", Platform: "linux", Enabled: true, NotAfter: time.Now().Add(2 * time.Hour)}); e != nil {
			return e
		}
		return tx.BindIssuer(l.trust)
	}))
	id := uuid.NewString()
	secret, e := s.Invite(ctx, actor, controller.InvitationSpec{ID: id, IssuerID: l.trust.IssuerID(), PrincipalID: l.request.PrincipalID, Profile: pki.Device, ExpiresAt: time.Now().Add(5 * time.Minute), NotAfter: l.request.NotAfter})
	testfixture.Must(t, e)
	testfixture.Must(t, s.ReserveEnrollment(ctx, actor, id, secret, l.request.AttemptID, l.request.CSR))
	testfixture.Must(t, s.IssueEnrollment(ctx, actor, id, l.trust, l.client))
	der, e := s.EnrollmentCertificate(ctx, actor, id, secret, l.request.AttemptID, l.request.CSR)
	testfixture.Must(t, e)
	receipt, e := l.s.Result(l.request.AttemptID)
	testfixture.Must(t, e)
	if !bytes.Equal(der, receipt.Certificate) {
		t.Fatal("controller registered a different issuer receipt")
	}
	summary, e := s.Summary(ctx)
	testfixture.Must(t, e)
	if summary.Certificates != 1 {
		t.Fatal("real issuance not registered")
	}
}
