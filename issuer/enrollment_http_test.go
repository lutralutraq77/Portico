package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/controller"
	"portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// This composes the actual restricted Smallstep authority and its mTLS/JWK
// provider with both controller endpoints and the ordinary enrollment client.
// Every listener is ephemeral loopback; no production trust or hardware is used.
func TestOrdinaryHTTPSWorkflowThroughRealIssuer(t *testing.T) {
	for _, profile := range []pki.Profile{pki.Device, pki.Connector} {
		t.Run(string(profile), func(t *testing.T) {
			l := newLab(t, profile)
			ctx := context.Background()
			s, err := controller.Open(ctx, t.TempDir())
			testfixture.Must(t, err)
			t.Cleanup(func() { testfixture.Must(t, s.Close()) })
			actor, user := uuid.NewString(), uuid.NewString()
			testfixture.Must(t, s.Update(ctx, actor, func(tx *controller.Tx) error {
				if profile == pki.Device {
					if err := tx.AddUser(controller.User{ID: user, Name: "Isolated HTTPS integration", Enabled: true}); err != nil {
						return err
					}
					if err := tx.AddDevice(controller.Device{ID: l.request.PrincipalID, UserID: user, Name: "Fixture", Platform: "linux", Enabled: true, NotAfter: time.Now().Add(2 * time.Hour)}); err != nil {
						return err
					}
				} else if err := tx.AddConnector(controller.Connector{ID: l.request.PrincipalID, Name: "Fixture", Version: "0.6.0-dev", Enabled: true}); err != nil {
					return err
				}
				return tx.BindIssuer(l.trust)
			}))
			root, rk := testfixture.Root(t)
			serverIdentity := testfixture.TLSIdentity(t, root, rk, true)
			endpoints := make([]enrollment.Endpoint, 2)
			for i := range endpoints {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				testfixture.Must(t, err)
				host := "localhost:" + strings.Split(listener.Addr().String(), ":")[1]
				cfg := controller.EnrollmentHTTPConfig{Host: host, ServerIdentity: serverIdentity, Trust: l.trust, Timeout: 5 * time.Second, MaxConnections: 4, MaxRequests: 2}
				var ingress *controller.EnrollmentHTTPServer
				if i == 0 {
					cfg.Provider = l.client
					ingress, err = s.NewEnrollmentRedemptionServer(cfg)
				} else {
					ingress, err = s.NewEnrollmentActivationServer(cfg)
				}
				testfixture.Must(t, err)
				done := make(chan error, 1)
				go func() { done <- ingress.Serve(listener) }()
				t.Cleanup(func() {
					stop, cancel := context.WithTimeout(ctx, 6*time.Second)
					defer cancel()
					testfixture.Must(t, ingress.Close(stop))
					select {
					case err := <-done:
						if !errors.Is(err, http.ErrServerClosed) {
							t.Errorf("ingress exit: %v", err)
						}
					case <-stop.Done():
						t.Error("ingress did not join")
					}
				})
				endpoints[i] = enrollment.Endpoint{URL: "https://" + host, ServerRootDER: root.Raw, ServerSPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo)}
			}
			id, attempt := uuid.NewString(), uuid.NewString()
			secret, err := s.Invite(ctx, actor, controller.InvitationSpec{ID: id, IssuerID: l.trust.IssuerID(), PrincipalID: l.request.PrincipalID, Profile: profile, ExpiresAt: time.Now().Add(5 * time.Minute), NotAfter: l.request.NotAfter})
			testfixture.Must(t, err)
			client, err := enrollment.New(enrollment.Config{Redemption: endpoints[0], Activation: endpoints[1], Trust: l.trust, PrincipalID: l.request.PrincipalID, NotAfter: l.request.NotAfter, Timeout: 5 * time.Second, MaxRequests: 1})
			testfixture.Must(t, err)
			t.Cleanup(client.Close)
			key := testfixture.Key(t)
			request, err := enrollment.NewRequest(id, secret, attempt, key)
			testfixture.Must(t, err)
			identity, err := client.Redeem(ctx, request, key)
			testfixture.Must(t, err)
			receipt, err := l.s.Result(attempt)
			testfixture.Must(t, err)
			if !bytes.Equal(receipt.Certificate, identity.Certificate[0]) || receipt.CSRHash != pki.Hash(request.CSR) {
				t.Fatal("network workflow changed issuer receipt")
			}
			serverTLS, err := s.ClientTLSConfig(serverIdentity, l.trust, false)
			testfixture.Must(t, err)
			probe := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			probe.TLS = serverTLS
			probe.Config.ErrorLog = log.New(io.Discard, "", 0)
			probe.StartTLS()
			t.Cleanup(probe.Close)
			roots := x509.NewCertPool()
			roots.AddCert(root)
			probeTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}}, DisableKeepAlives: true, Proxy: nil}
			t.Cleanup(probeTransport.CloseIdleConnections)
			probeClient := &http.Client{Transport: probeTransport, Timeout: 5 * time.Second}
			assertLive := func(want bool) {
				t.Helper()
				response, err := probeClient.Get(strings.Replace(probe.URL, "127.0.0.1", "localhost", 1))
				live := false
				if err == nil {
					live = response.StatusCode == http.StatusNoContent
					_ = response.Body.Close()
				}
				if live != want {
					t.Fatalf("live TLS authentication=%v want %v (error %v)", live, want, err)
				}
			}
			assertLive(false)
			testfixture.Must(t, client.Activate(ctx, id, identity))
			assertLive(true)
			request, err = enrollment.NewRequest(id, secret, attempt, key)
			testfixture.Must(t, err)
			retry, err := client.Redeem(ctx, request, key)
			testfixture.Must(t, err)
			if !bytes.Equal(retry.Certificate[0], identity.Certificate[0]) {
				t.Fatal("retry signed another certificate")
			}
			testfixture.Must(t, s.Update(ctx, actor, func(tx *controller.Tx) error { return tx.RevokeEnrollment(id) }))
			assertLive(false)
			if err := client.Activate(ctx, id, identity); err == nil {
				t.Fatal("revoked identity activated")
			}
			summary, err := s.Summary(ctx)
			testfixture.Must(t, err)
			if summary.Certificates != 1 {
				t.Fatal("unexpected issuer registration count")
			}
		})
	}
}
