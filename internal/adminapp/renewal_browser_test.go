//go:build dashboardbrowser

package adminapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/adminauth"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/controller"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type browserRenewalIssuer func(context.Context, controller.IssuanceRequest) ([]byte, error)

func (f browserRenewalIssuer) Issue(ctx context.Context, request controller.IssuanceRequest) ([]byte, error) {
	return f(ctx, request)
}

// This portable actual-window test uses the real controller, WebAuthn verifier,
// native orchestrator and distinct TLS listeners. Credential disk barriers and
// encrypted-key unlocking are qualified separately on Linux, not simulated here.
func TestNativeAdministratorRenewalBrowser(t *testing.T) {
	executable, report := filepath.Clean(os.Getenv("PORTICO_NATIVE_EXECUTABLE")), filepath.Clean(os.Getenv("PORTICO_BROWSER_REPORT"))
	if !filepath.IsAbs(executable) || !filepath.IsAbs(report) {
		t.Fatal("renewal browser requires absolute runtime and report paths")
	}
	f := nativeRenewalSeed(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	store, err := controller.Open(ctx, t.TempDir())
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = store.Close() })
	user := controller.User{ID: controller.NewID(), Name: "Renewal administrator", Enabled: true}
	device := controller.Device{ID: f.key.principal, UserID: user.ID, Name: "Native renewal fixture", Platform: "linux", Enabled: true, NotAfter: time.Now().Add(3 * time.Hour)}
	testfixture.Must(t, store.Update(ctx, user.ID, func(tx *controller.Tx) error {
		if err := tx.AddUser(user); err != nil {
			return err
		}
		if err := tx.AddDevice(device); err != nil {
			return err
		}
		return tx.RegisterAdminDevice(user.ID, device.ID, f.key.trust, f.config.leaf)
	}))
	ordinary := func(profile pki.Profile) *pki.Trust {
		root, rootKey := testfixture.Root(t)
		key := testfixture.Key(t)
		ca := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, key.Public(), rootKey)
		trust, err := pki.NewTrust(pki.Config{DeploymentID: f.key.trust.DeploymentID(), IssuerID: controller.NewID(), Profile: profile, RootDER: root.Raw, IssuerDER: ca.Raw})
		testfixture.Must(t, err)
		return trust
	}
	engine, err := controller.NewPolicyEngine(store, controller.PolicyConfig{DeviceTrust: ordinary(pki.Device), ConnectorTrust: ordinary(pki.Connector), ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}, MaxSessions: 16, MaxDeviceSessions: 4, MaxConnectorSessions: 8, SessionLifetime: time.Hour, LeaseLifetime: 2 * time.Second, ActivationLifetime: time.Second})
	testfixture.Must(t, err)
	management, err := net.Listen("tcp", "127.0.0.1:0")
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = management.Close() })
	activation, err := net.Listen("tcp", "127.0.0.1:0")
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = activation.Close() })
	managementHost, activationHost := net.JoinHostPort("admin.portico.test", portOf(management)), net.JoinHostPort("admin.portico.test", portOf(activation))
	id, roots := testfixture.ChromiumAttestation(t)
	verifier, err := adminauth.New(adminauth.Config{Origin: "https://" + managementHost, ValidUntil: time.Now().Add(time.Hour), Models: []adminauth.Model{{AAGUID: id, RootsDER: roots}}})
	testfixture.Must(t, err)
	root, rootKey := testfixture.Root(t)
	serverKey := testfixture.Key(t)
	serverLeaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"admin.portico.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, serverKey.Public(), rootKey)
	identity := tls.Certificate{Certificate: [][]byte{serverLeaf.Raw}, PrivateKey: serverKey, Leaf: serverLeaf}
	var issued atomic.Int32
	server, err := engine.NewHTTPServer(controller.PolicyHTTPConfig{Profile: pki.Administrator, Host: managementHost, ServerIdentity: identity, AdministratorTrust: f.key.trust, AdministratorVerifier: verifier, AdministratorRenewalIssuer: browserRenewalIssuer(func(_ context.Context, request controller.IssuanceRequest) ([]byte, error) {
		if request.Profile != pki.Administrator || request.PrincipalID != f.key.principal || request.IssuerID != f.key.trust.IssuerID() || request.DeploymentID != f.key.trust.DeploymentID() {
			return nil, controller.ErrDenied
		}
		issued.Add(1)
		return f.sign(request.CSR, request.NotBefore, request.NotAfter), nil
	})})
	testfixture.Must(t, err)
	activated, err := store.NewAdminRenewalActivationServer(controller.AdminRenewalActivationConfig{Host: activationHost, ServerIdentity: identity, Trust: f.key.trust, Timeout: 5 * time.Second, MaxConnections: 4, MaxRequests: 2})
	testfixture.Must(t, err)
	managementDone, activationDone := make(chan error, 1), make(chan error, 1)
	go func() { managementDone <- server.Serve(management) }()
	go func() { activationDone <- activated.Serve(activation) }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		testfixture.Must(t, server.Close(stop))
		testfixture.Must(t, activated.Close(stop))
		for _, done := range []chan error{managementDone, activationDone} {
			if err := <-done; err != http.ErrServerClosed {
				t.Errorf("renewal fixture shutdown: %v", err)
			}
		}
	})
	config := func(host string, listener net.Listener) adminbridge.Config {
		return adminbridge.Config{Origin: "https://" + host, ServerSPKI: pki.Hash(identity.Leaf.RawSubjectPublicKeyInfo), ServerRootDER: root.Raw, AdministratorTrust: f.key.trust, BootstrapAddress: listener.Addr().String(), Timeout: 5 * time.Second, Lifetime: 2 * time.Minute, ClockHealth: func() (time.Duration, error) { return time.Millisecond, nil }}
	}
	f.config.bridge = config(managementHost, management)
	activationConfig := config(activationHost, activation)
	f.config.renewal = &activationConfig
	bridgeConfig := f.config.bridge
	bridgeConfig.Identity, err = f.key.Identity(f.config.leaf)
	testfixture.Must(t, err)
	var approvalCalls atomic.Int32
	bridgeConfig.RenewalHandler = func(ctx context.Context, request adminbridge.Request, send adminbridge.RenewalExchange) (adminbridge.Response, error) {
		if request.Path == adminrenewal.ApprovePath {
			approvalCalls.Add(1)
		}
		return f.native.Handle(ctx, request, send)
	}
	client, err := adminbridge.New(ctx, bridgeConfig)
	testfixture.Must(t, err)
	defer client.Close()
	entry, err := filepath.Abs(filepath.Join("..", "..", "scripts", "test-dashboard-renewal-native.cjs"))
	testfixture.Must(t, err)
	testfixture.Must(t, adminbridge.Run(ctx, client, adminbridge.Launch{Executable: executable, EntryPoint: entry, StateDirectory: report}))
	if approvalCalls.Load() != 1 || issued.Load() != 1 || !f.native.completed || f.native.journal.record.Pending != nil || pki.Hash(f.native.journal.record.Certificate) == pki.Hash(f.config.leaf) {
		t.Fatal("actual window failed to complete and retain one approved renewal")
	}
	// Reopening composes the saved public certificate with the same native key.
	f.reopen(t)
	bridgeConfig.RenewalHandler = f.native.Handle
	bridgeConfig.Identity, err = f.key.Identity(f.native.journal.record.Certificate)
	testfixture.Must(t, err)
	current, err := adminbridge.New(ctx, bridgeConfig)
	testfixture.Must(t, err)
	defer current.Close()
	response, err := current.Exchange(ctx, adminbridge.Request{Method: http.MethodGet, Path: "/admin"})
	testfixture.Must(t, err)
	if response.Status != http.StatusOK {
		t.Fatal("reopened native identity was not active in the real controller")
	}
	oldIdentity, err := f.key.Identity(f.config.leaf)
	testfixture.Must(t, err)
	bridgeConfig.Identity, bridgeConfig.RenewalHandler = oldIdentity, nil
	old, err := adminbridge.New(ctx, bridgeConfig)
	testfixture.Must(t, err)
	defer old.Close()
	if _, err := old.Exchange(ctx, adminbridge.Request{Method: http.MethodGet, Path: "/admin"}); err == nil {
		t.Fatal("retired native certificate was accepted by the real controller")
	}
	t.Log("actual native window, two separately registered/tested virtual keys, fresh WebAuthn approval, real controller HTTPS issuance/activation, retained certificate, reopened current TLS and old identity rejection passed; memory storage fixture and local issuer signer are explicit")
}

func portOf(listener net.Listener) string {
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return port
}
