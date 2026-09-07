package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConnectorDNSProfileRejectsOldExtraAndForeignNames(t *testing.T) {
	for _, kind := range []string{"old_uri_only", "foreign_name", "duplicate_name", "wildcard", "foreign_uri", "missing_uri", "client_only"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t, Connector)
			switch kind {
			case "old_uri_only":
				f.leaf.DNSNames = nil
			case "foreign_name":
				f.leaf.DNSNames = []string{"other.portico.invalid"}
			case "duplicate_name":
				f.leaf.DNSNames = append(f.leaf.DNSNames, f.leaf.DNSNames[0])
			case "wildcard":
				f.leaf.DNSNames = []string{"*.connector.portico.invalid"}
			case "foreign_uri":
				f.leaf.URIs[0].Path = "/connector/" + uuid.NewString()
			case "missing_uri":
				f.leaf.URIs = nil
			case "client_only":
				f.leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			der := signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
			if _, e := f.trust.Verify(der, f.principal, f.now); e == nil {
				t.Fatal("invalid connector profile accepted")
			}
		})
	}
}

func connectorTLSFixtures(t *testing.T) (*tls.Config, *tls.Config, fixture) {
	t.Helper()
	server, client := setup(t, Connector), setup(t, Device)
	client.trust.deployment = server.trust.deployment
	u, e := IdentityURI(server.trust.deployment, Device, client.principal)
	if e != nil {
		t.Fatal(e)
	}
	client.leaf.URIs = []*url.URL{u}
	local := tls.Certificate{Certificate: [][]byte{signed(t, client.leaf, client.issuer, &client.deviceKey.PublicKey, client.issuerKey)}, PrivateKey: client.deviceKey}
	local, e = client.trust.TLSIdentity(local)
	if e != nil {
		t.Fatal(e)
	}
	remote := tls.Certificate{Certificate: [][]byte{signed(t, server.leaf, server.issuer, &server.deviceKey.PublicKey, server.issuerKey)}, PrivateKey: server.deviceKey}
	sc, e := server.trust.ConnectorServerTLS(remote, client.trust)
	if e != nil {
		t.Fatal(e)
	}
	cc, e := server.trust.ConnectorClientTLS(local, server.principal)
	if e != nil {
		t.Fatal(e)
	}
	return sc, cc, server
}

func exchangeTLS(t *testing.T, server, client *tls.Config) (error, error) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			result <- e
			return
		}
		defer func() { _ = conn.Close() }()
		c := tls.Server(conn, server)
		if e = c.HandshakeContext(ctx); e == nil {
			_, e = c.Write([]byte{42})
		}
		result <- e
	}()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = conn.Close() }()
	c := tls.Client(conn, client)
	e = c.HandshakeContext(ctx)
	if e == nil {
		var b [1]byte
		_, e = c.Read(b[:])
		if e == nil && b[0] != 42 {
			t.Fatal("TLS application byte changed")
		}
	}
	return e, <-result
}

func TestConnectorTLSUsesStandardNameAndChainChecks(t *testing.T) {
	for _, kind := range []string{"valid", "wrong_expected_connector", "untrusted_root", "missing_device", "tls12", "wrong_typed_identity"} {
		t.Run(kind, func(t *testing.T) {
			sc, cc, f := connectorTLSFixtures(t)
			if cc.InsecureSkipVerify || cc.ServerName == "" || cc.RootCAs == nil || sc.ClientAuth != tls.RequireAndVerifyClientCert {
				t.Fatal("TLS standard verification disabled")
			}
			switch kind {
			case "wrong_expected_connector":
				cc.ServerName, _ = ConnectorName(f.trust.deployment, uuid.NewString())
			case "untrusted_root":
				cc.RootCAs = x509.NewCertPool()
			case "missing_device":
				cc.Certificates = nil
			case "tls12":
				cc.MinVersion = tls.VersionTLS12
				cc.MaxVersion = tls.VersionTLS12
			case "wrong_typed_identity":
				// A DNS-valid certificate still must pass the independent typed URI
				// check; the normal hostname validator alone cannot establish role.
				f.leaf.URIs[0].Path = "/device/" + f.principal
				sc.Certificates[0].Certificate[0] = signed(t, f.leaf, f.issuer, &f.deviceKey.PublicKey, f.issuerKey)
			}
			clientError, serverError := exchangeTLS(t, sc, cc)
			if kind == "valid" {
				if clientError != nil || serverError != nil {
					t.Fatalf("valid TLS failed: %v, %v", clientError, serverError)
				}
			} else if clientError == nil && serverError == nil {
				t.Fatal("untrusted TLS accepted")
			}
		})
	}
}
