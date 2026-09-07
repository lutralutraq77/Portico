package issuer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func serverTLSForTest(root *x509.Certificate, identity tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{identity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
}

func TestIssuerAdapterRejectsUnpinnedTLSAndHostileResponses(t *testing.T) {
	root, rk := testfixture.Root(t)
	ik := testfixture.Key(t)
	intermediate := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated client test issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &ik.PublicKey, rk)
	trust, e := pki.NewTrust(pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: pki.Device, RootDER: root.Raw, IssuerDER: intermediate.Raw})
	testfixture.Must(t, e)
	key := testfixture.Key(t)
	csr, e := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, key)
	testfixture.Must(t, e)
	r := pki.IssuanceRequest{AttemptID: uuid.NewString(), DeploymentID: trust.DeploymentID(), IssuerID: trust.IssuerID(), PrincipalID: uuid.NewString(), Profile: pki.Device, CSR: csr, NotBefore: time.Now().Truncate(time.Second), NotAfter: time.Now().Truncate(time.Second).Add(time.Hour)}
	commRoot, commKey := testfixture.Root(t)
	serverIdentity := testfixture.TLSIdentity(t, commRoot, commKey, true)
	clientIdentity := testfixture.TLSIdentity(t, commRoot, commKey, false)
	for _, name := range []string{"pin", "root", "redirect", "oversized", "unknown_field", "trailing_value", "bad_pem", "failure", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				switch name {
				case "redirect":
					w.Header().Set("Location", "https://should-never-be-contacted.invalid/")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "oversized":
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, strings.Repeat("x", MaxBody+1))
				case "unknown_field":
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"crt":"","unexpected":true}`)
				case "trailing_value":
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"crt":""}{"crt":""}`)
				case "bad_pem":
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"crt":"not a certificate"}`)
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			s := httptest.NewUnstartedServer(h)
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = serverTLSForTest(commRoot, serverIdentity)
			s.StartTLS()
			defer s.Close()
			cfg := Config{Endpoint: strings.Replace(s.URL, "127.0.0.1", "localhost", 1), Provisioner: "fixture", KeyID: uuid.NewString(), ProvisionerKey: testfixture.Key(t), ServerRootDER: commRoot.Raw, ServerSPKI: pki.Hash(serverIdentity.Leaf.RawSubjectPublicKeyInfo), ControllerIdentity: clientIdentity, Trust: trust}
			if name == "pin" {
				cfg.ServerSPKI = strings.Repeat("a", 64)
			}
			if name == "root" {
				cfg.ServerRootDER = root.Raw
			}
			client, e := New(cfg)
			testfixture.Must(t, e)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancelled" {
				cancel()
			}
			if _, e = client.Issue(ctx, r); e != ErrRejected {
				t.Fatalf("unexpected result %v", e)
			}
			want := int32(1)
			if name == "pin" || name == "root" || name == "cancelled" {
				want = 0
			}
			if requests.Load() != want {
				t.Fatal("request escaped pin/context check or was retried")
			}
		})
	}
}
