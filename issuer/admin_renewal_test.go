package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/controller"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// This uses the actual restricted Smallstep service over pinned mTLS/JWK, the
// controller's durable approval/issuance records, virtual WebAuthn factors and
// real TLS proofs of both administrator certificates. No signing mock is used.
func TestAdministratorRenewalThroughRealRestrictedIssuer(t *testing.T) {
	l := newLab(t, pki.Administrator)
	ctx := context.Background()
	key := testfixture.Key(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	testfixture.Must(t, err)
	initial := l.request
	initial.CSR = csr
	leaf, err := l.client.Issue(ctx, initial)
	testfixture.Must(t, err)
	s, err := controller.Open(ctx, t.TempDir())
	testfixture.Must(t, err)
	defer s.Close()
	user := uuid.NewString()
	testfixture.Must(t, s.Update(ctx, user, func(tx *controller.Tx) error {
		if err := tx.AddUser(controller.User{ID: user, Name: "Isolated renewal owner", Enabled: true}); err != nil {
			return err
		}
		if err := tx.AddDevice(controller.Device{ID: initial.PrincipalID, UserID: user, Name: "Isolated administrator", Platform: "linux", Enabled: true, NotAfter: time.Now().Add(3 * time.Hour)}); err != nil {
			return err
		}
		return tx.RegisterAdminDevice(user, initial.PrincipalID, l.trust, leaf)
	}))
	root, rootKey := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, root, rootKey, true)
	currentTLS, err := s.AdminTLSConfig(serverIdentity, l.trust)
	testfixture.Must(t, err)
	activationTLS, err := s.AdminRenewalTLSConfig(serverIdentity, l.trust)
	testfixture.Must(t, err)
	oldIdentity := tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: key}
	current, err := renewalTLSProof(t, currentTLS, oldIdentity, root)
	testfixture.Must(t, err)
	keys := []*testfixture.VirtualKey{testfixture.Virtual(t), testfixture.Virtual(t)}
	models := make([]adminauth.Model, 0, len(keys))
	for _, factor := range keys {
		models = append(models, adminauth.Model{AAGUID: factor.AAGUID.String(), RootsDER: [][]byte{factor.Root.Raw}})
	}
	v, err := adminauth.New(adminauth.Config{Origin: "https://admin.portico.test", Models: models, ValidUntil: time.Now().Add(time.Hour)})
	testfixture.Must(t, err)
	for _, factor := range keys {
		page, err := s.DashboardInventory(ctx, current, l.trust, controller.DashboardRequest{Section: "factors", Limit: 8})
		testfixture.Must(t, err)
		challenge, err := s.BeginFactor(ctx, current, l.trust, v, controller.FactorRequest{Kind: "bootstrap-factor", PolicyRevision: page.PolicyRevision})
		testfixture.Must(t, err)
		response := factor.Register(t, base64.RawURLEncoding.EncodeToString(challenge.Challenge.Registration.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
		_, err = s.FinishFactor(ctx, current, l.trust, v, challenge.Challenge.ID, response)
		testfixture.Must(t, err)
		approval, err := s.BeginAdminOperation(ctx, current, l.trust, v, controller.AdminOperation{Kind: "test-factor", TargetID: challenge.FactorID})
		testfixture.Must(t, err)
		response = factor.Assert(t, base64.RawURLEncoding.EncodeToString(approval.Approval.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
		_, err = s.FinishFactor(ctx, current, l.trust, v, approval.ID, response)
		testfixture.Must(t, err)
	}
	id := uuid.NewString()
	until := initial.NotAfter.Add(30 * time.Minute)
	challenge, err := s.BeginAdminRenewal(ctx, current, l.trust, v, id, controller.AdminRenewalSpec{CSR: csr, NotAfter: until})
	testfixture.Must(t, err)
	response := keys[1].Assert(t, base64.RawURLEncoding.EncodeToString(challenge.Approval.Response.Challenge), "https://admin.portico.test", "admin.portico.test", 5)
	approved, err := s.FinishAdminRenewal(ctx, current, l.trust, v, challenge.ID, response)
	testfixture.Must(t, err)
	if approved != id {
		t.Fatal("renewal approval changed identifier")
	}
	testfixture.Must(t, s.IssueAdminRenewal(ctx, user, id, l.trust, l.client))
	candidateDER, err := s.AdminRenewalCertificate(ctx, current, l.trust, id)
	testfixture.Must(t, err)
	receipt, err := l.s.Result(id)
	testfixture.Must(t, err)
	if !bytes.Equal(receipt.Certificate, candidateDER) || receipt.CSRHash != pki.Hash(csr) {
		t.Fatal("durable issuer receipt differs from approved renewal")
	}
	credential, err := l.trust.Verify(candidateDER, initial.PrincipalID, time.Now())
	testfixture.Must(t, err)
	if credential.Profile != pki.Administrator || !credential.NotAfter.Equal(until) {
		t.Fatal("restricted issuer changed renewal profile or lifetime")
	}
	if err = s.IssueAdminRenewal(ctx, user, id, l.trust, l.client); err == nil {
		t.Fatal("approved attempt signed a second time")
	}
	identity := tls.Certificate{Certificate: [][]byte{candidateDER}, PrivateKey: key}
	if _, err = renewalTLSProof(t, currentTLS, identity, root); err == nil {
		t.Fatal("unactivated issuer result entered the administration listener")
	}
	candidate, err := renewalTLSProof(t, activationTLS, identity, root)
	testfixture.Must(t, err)
	if _, err = s.DashboardInventory(ctx, candidate, l.trust, controller.DashboardRequest{Section: "users", Limit: 8}); err == nil {
		t.Fatal("activation-only candidate read administrator inventory")
	}
	activateAdministratorHTTPS(t, s, l.trust, serverIdentity, root, identity, id)
	if _, err = renewalTLSProof(t, currentTLS, oldIdentity, root); err == nil {
		t.Fatal("old administrator certificate retained TLS authority")
	}
	if _, err = s.DashboardInventory(ctx, current, l.trust, controller.DashboardRequest{Section: "users", Limit: 8}); err == nil {
		t.Fatal("old established connection retained administrator access")
	}
	activated, err := renewalTLSProof(t, currentTLS, identity, root)
	testfixture.Must(t, err)
	_, err = s.DashboardInventory(ctx, activated, l.trust, controller.DashboardRequest{Section: "users", Limit: 8})
	testfixture.Must(t, err)
	t.Log("real restricted administrator issuance, two separately tested virtual factors, backup-key approval, singular renewal, durable issuer receipt and separate HTTPS activation verified")
}

func activateAdministratorHTTPS(t *testing.T, s *controller.Store, trust *pki.Trust, serverIdentity tls.Certificate, root *x509.Certificate, identity tls.Certificate, id string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	testfixture.Must(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	testfixture.Must(t, err)
	host := net.JoinHostPort("localhost", port)
	server, err := s.NewAdminRenewalActivationServer(controller.AdminRenewalActivationConfig{Host: host, ServerIdentity: serverIdentity, Trust: trust, Timeout: 3 * time.Second, MaxConnections: 2, MaxRequests: 1})
	testfixture.Must(t, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		testfixture.Must(t, server.Close(stop))
		if err := <-done; err != http.ErrServerClosed {
			t.Errorf("administrator activation HTTP shutdown: %v", err)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(root)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := json.Marshal(adminrenewal.ActivateRequest{Version: 1, RenewalID: id})
	testfixture.Must(t, err)
	request, err := http.NewRequest(http.MethodPost, "https://"+host+adminrenewal.ActivatePath, bytes.NewReader(body))
	testfixture.Must(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://"+host)
	response, err := client.Do(request)
	testfixture.Must(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, adminrenewal.MaxActivationBody+1))
	testfixture.Must(t, err)
	if response.StatusCode != http.StatusOK || len(data) > adminrenewal.MaxActivationBody || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("renewal HTTPS activation rejected or exceeded its response scope")
	}
	var result adminrenewal.Activated
	testfixture.Must(t, json.Unmarshal(data, &result))
	if result.Version != 1 || result.RenewalID != id || result.CertificateSHA256 != pki.Hash(identity.Certificate[0]) {
		t.Fatal("HTTPS activation response lost its exact certificate binding")
	}
}

func renewalTLSProof(t *testing.T, serverConfig *tls.Config, identity tls.Certificate, root *x509.Certificate) (*tls.Conn, error) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	server := tls.Server(a, serverConfig)
	client := tls.Client(b, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{identity}})
	done := make(chan error, 1)
	go func() {
		err := server.HandshakeContext(context.Background())
		if err != nil {
			_ = a.Close()
		}
		done <- err
	}()
	clientError := client.HandshakeContext(context.Background())
	if clientError != nil {
		_ = b.Close()
	} else {
		go func() { var one [1]byte; _, _ = client.Read(one[:]) }()
	}
	serverError := <-done
	if clientError != nil {
		return nil, clientError
	}
	return server, serverError
}
