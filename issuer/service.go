// Package service is a separate, restricted step-ca process boundary. Only its
// authenticated sign operation is exposed; the stock step-ca router is absent.
package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	stepjose "go.step.sm/crypto/jose"
	"portico.local/portico/internal/issuer"
	"portico.local/portico/internal/pki"
)

type Config struct {
	Endpoint, Provisioner, KeyID, DatabasePath string
	TrustConfig                                pki.Config
	IssuerSigner                               crypto.Signer
	ProvisionerPublicKey                       jose.JSONWebKey
	ServerIdentity                             tls.Certificate
	ControllerRootDER                          []byte
	ControllerSPKI                             string
}
type Service struct {
	ca         *authority.Authority
	database   *db.DB
	server     *http.Server
	trust      *pki.Trust
	config     Config
	key        jose.JSONWebKey
	closeOnce  sync.Once
	closeError error
}

type redactedDB struct{ *db.DB }

func (d redactedDB) UseToken(id, token string) (bool, error) {
	return d.DB.UseToken(id, pki.Hash([]byte(token)))
}

var receiptTable = []byte("portico_results_v1")
var bindingTable = []byte("portico_binding_v1")

type Receipt struct {
	AttemptID, CSRHash, PrincipalID string
	Certificate                     []byte
}

// Result is a local operator lookup, not an HTTP endpoint. Missing receipts
// remain ambiguous and must never be converted into a second signing attempt.
func (s *Service) Result(attempt string) (Receipt, error) {
	if !pki.ValidID(attempt) {
		return Receipt{}, issuer.ErrRejected
	}
	b, e := s.database.Get(receiptTable, []byte(attempt))
	if e != nil {
		return Receipt{}, issuer.ErrRejected
	}
	var r Receipt
	if issuer.Decode(b, &r) != nil || r.AttemptID != attempt {
		return Receipt{}, issuer.ErrRejected
	}
	if _, e = s.trust.Verify(r.Certificate, r.PrincipalID, time.Now()); e != nil {
		return Receipt{}, issuer.ErrRejected
	}
	return r, nil
}

func New(c Config) (*Service, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Provisioner == "" || c.KeyID == "" || !filepath.IsAbs(c.DatabasePath) || strings.HasPrefix(c.DatabasePath, "\\\\") || c.IssuerSigner == nil || len(c.ServerIdentity.Certificate) == 0 || c.ServerIdentity.PrivateKey == nil || len(c.ControllerSPKI) != 64 || !c.ProvisionerPublicKey.IsPublic() {
		return nil, issuer.ErrRejected
	}
	trust, e := pki.NewTrust(c.TrustConfig)
	if e != nil {
		return nil, issuer.ErrRejected
	}
	root, e := x509.ParseCertificate(c.TrustConfig.RootDER)
	if e != nil {
		return nil, issuer.ErrRejected
	}
	intermediate, e := x509.ParseCertificate(c.TrustConfig.IssuerDER)
	if e != nil {
		return nil, issuer.ErrRejected
	}
	spki, e := x509.MarshalPKIXPublicKey(c.IssuerSigner.Public())
	if e != nil || !bytes.Equal(spki, intermediate.RawSubjectPublicKeyInfo) {
		return nil, issuer.ErrRejected
	}
	controllerRoot, e := x509.ParseCertificate(c.ControllerRootDER)
	if e != nil || !controllerRoot.IsCA {
		return nil, issuer.ErrRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(controllerRoot)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.ServerIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || pki.Hash(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != c.ControllerSPKI {
			return issuer.ErrRejected
		}
		return nil
	}
	publicJSON, e := json.Marshal(c.ProvisionerPublicKey)
	if e != nil {
		return nil, issuer.ErrRejected
	}
	var publicKey stepjose.JSONWebKey
	if json.Unmarshal(publicJSON, &publicKey) != nil || publicKey.Algorithm != "ES256" || publicKey.KeyID != c.KeyID {
		return nil, issuer.ErrRejected
	}
	eku := `["clientAuth"]`
	if trust.Profile() == pki.Connector {
		eku = `["clientAuth","serverAuth"]`
	}
	template := `{"subject":{},"sans":{{ toJson .SANs }},"keyUsage":["digitalSignature"],"extKeyUsage":` + eku + `,"basicConstraints":{"isCA":false}}`
	on, off := true, false
	claims := &provisioner.Claims{MinTLSDur: &provisioner.Duration{Duration: time.Second}, MaxTLSDur: &provisioner.Duration{Duration: 24 * time.Hour}, DefaultTLSDur: &provisioner.Duration{Duration: time.Hour}, DisableRenewal: &on, AllowRenewalAfterExpiry: &off, EnableSSHCA: &off, DisableSmallstepExtensions: &on}
	jwk := &provisioner.JWK{Type: "JWK", Name: c.Provisioner, Key: &publicKey, Claims: claims, Options: &provisioner.Options{X509: &provisioner.X509Options{Template: template}}}
	opened, e := db.New(&db.Config{Type: "bbolt", DataSource: c.DatabasePath})
	if e != nil {
		return nil, issuer.ErrRejected
	}
	database, ok := opened.(*db.DB)
	if !ok {
		_ = opened.Shutdown()
		return nil, issuer.ErrRejected
	}
	success := false
	defer func() {
		if !success {
			_ = database.Shutdown()
		}
	}()
	if database.CreateTable(receiptTable) != nil || database.CreateTable(bindingTable) != nil {
		return nil, issuer.ErrRejected
	}
	binding, _ := json.Marshal([]string{trust.DeploymentID(), trust.IssuerID(), string(trust.Profile()), trust.RootFingerprint(), trust.IssuerFingerprint(), c.Provisioner, c.KeyID, pki.Hash(publicJSON)})
	stored, swapped, e := database.CmpAndSwap(bindingTable, []byte("identity"), nil, binding)
	if e != nil || (!swapped && !bytes.Equal(stored, binding)) {
		return nil, issuer.ErrRejected
	}
	ca, e := authority.NewEmbedded(authority.WithConfig(&config.Config{DNSNames: []string{u.Host}, AuthorityConfig: &config.AuthConfig{Provisioners: provisioner.List{jwk}, Claims: claims, Backdate: &provisioner.Duration{Duration: 0}}}), authority.WithDatabase(redactedDB{database}), authority.WithX509RootCerts(root), authority.WithX509Signer(intermediate, c.IssuerSigner), authority.WithQuietInit())
	if e != nil {
		return nil, issuer.ErrRejected
	}
	s := &Service{ca: ca, database: database, trust: trust, config: c, key: c.ProvisionerPublicKey}
	s.server = &http.Server{Handler: http.HandlerFunc(s.sign), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	success = true
	return s, nil
}

// Serve wraps every supplied listener in the service-owned TLS policy. There is
// no alternate insecure listener, CA router, ACME or renewal/rekey API.
func (s *Service) Serve(l net.Listener) error {
	return s.server.Serve(tls.NewListener(l, s.server.TLSConfig))
}
func (s *Service) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		if e := s.server.Shutdown(ctx); e != nil {
			_ = s.server.Close()
		}
		s.closeError = s.ca.Shutdown()
	})
	return s.closeError
}

func (s *Service) sign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "request rejected", http.StatusForbidden) }
	if r.Method != http.MethodPost || r.URL.Path != issuer.SignPath || r.URL.RawQuery != "" || r.Host != strings.TrimPrefix(s.config.Endpoint, "https://") || r.Header.Get("Content-Type") != "application/json" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		fail()
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, issuer.MaxBody))
	if e != nil {
		fail()
		return
	}
	var req issuer.SignRequest
	if issuer.Decode(b, &req) != nil {
		fail()
		return
	}
	token, e := jwt.ParseSigned(req.Token, []jose.SignatureAlgorithm{jose.ES256})
	if e != nil || len(token.Headers) != 1 || token.Headers[0].KeyID != s.config.KeyID {
		fail()
		return
	}
	var claims issuer.Claims
	if token.Claims(s.key, &claims) != nil || claims.ValidateWithLeeway(jwt.Expected{Issuer: s.config.Provisioner, AnyAudience: jwt.Audience{s.config.Endpoint + issuer.SignPath}, Time: time.Now()}, 0) != nil || claims.ValidateApproval(s.trust, time.Now()) != nil {
		fail()
		return
	}
	block, rest := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		fail()
		return
	}
	csr, e := pki.ParseCSR(block.Bytes)
	if e != nil {
		fail()
		return
	}
	sum := sha256.Sum256(csr.Raw)
	if claims.Confirmation.Fingerprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
		fail()
		return
	}
	ctx := provisioner.NewContextWithMethod(r.Context(), provisioner.SignMethod)
	opts, e := s.ca.Authorize(ctx, req.Token)
	if e != nil {
		fail()
		return
	}
	chain, e := s.ca.SignWithContext(ctx, csr, provisioner.SignOptions{NotBefore: provisioner.NewTimeDuration(claims.Approval.NotBefore), NotAfter: provisioner.NewTimeDuration(claims.Approval.NotAfter)}, opts...)
	if e != nil || len(chain) == 0 {
		fail()
		return
	}
	cred, e := s.trust.Verify(chain[0].Raw, claims.Approval.PrincipalID, time.Now())
	if e != nil || cred.SPKISHA256 != pki.Hash(csr.RawSubjectPublicKeyInfo) || !cred.NotBefore.Equal(claims.Approval.NotBefore) || !cred.NotAfter.Equal(claims.Approval.NotAfter) {
		fail()
		return
	}
	receipt, e := json.Marshal(Receipt{AttemptID: claims.ID, CSRHash: pki.Hash(csr.Raw), PrincipalID: claims.Approval.PrincipalID, Certificate: chain[0].Raw})
	if e != nil || s.database.Set(receiptTable, []byte(claims.ID), receipt) != nil {
		fail()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(issuer.SignResponse{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw}))})
}
