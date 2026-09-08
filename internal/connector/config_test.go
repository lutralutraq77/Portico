package connector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func configFixture(t *testing.T) (FileConfig, map[string][]byte) {
	t.Helper()
	const deployment = "7ec6af2a-a7ed-4f6e-894b-70f530c88dd3"
	const deviceIssuer = "2846c6fd-bcef-453a-8b8e-13e681bf6004"
	const connectorIssuer = "3aa6fcd1-e757-453d-8509-bc4c6d46761c"
	const principal = "9f61c38c-5b90-4581-8b87-5c54ffca9d0d"
	files := map[string][]byte{}
	write := func(name, kind string, b []byte) string {
		path := "/config/" + name
		files[path] = pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b})
		return path
	}
	root, rk := testfixture.Root(t)
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issuerKey := newKey()
	now := time.Now()
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture connector issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &issuerKey.PublicKey, rk)
	device := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "fixture device issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &newKey().PublicKey, rk)
	uri, err := pki.IdentityURI(deployment, pki.Connector, principal)
	if err != nil {
		t.Fatal(err)
	}
	name, err := pki.ConnectorName(deployment, principal)
	if err != nil {
		t.Fatal(err)
	}
	key := newKey()
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(4), NotBefore: now.Add(-time.Second), NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, DNSNames: []string{name}}, issuer, &key.PublicKey, issuerKey)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := write("root.pem", "CERTIFICATE", root.Raw)
	endpoint := EndpointFiles{URL: "https://localhost:8443", RootCertificateFile: rootPath, SPKI: pki.Hash(root.RawSubjectPublicKeyInfo)}
	return FileConfig{Version: 1, DeploymentID: deployment, CertificateID: "3f585ecf-6303-48d3-8efd-844fda0b8b87", Devices: TrustFiles{deviceIssuer, rootPath, write("device.pem", "CERTIFICATE", device.Raw)}, Connectors: TrustFiles{connectorIssuer, rootPath, write("connector.pem", "CERTIFICATE", issuer.Raw)}, IdentityCertificateFile: write("identity.pem", "CERTIFICATE", leaf.Raw), IdentityKeyFile: write("key.pem", "PRIVATE KEY", der), Control: endpoint, Carrier: endpoint, Destinations: []DestinationFile{{ResourceID: "84c40359-9c27-498e-adb7-190b00f70a63", Revision: 1, Address: "192.0.2.10", Port: 443, Protocol: "tcp"}}, ProtectedNetworks: []string{"10.99.0.0/16"}, Workers: 2, MaxDeviceSessions: 1, OperationTimeoutMillis: 5000, IdleTimeoutSeconds: 60}, files
}

func TestConfigurationLoadsPinnedLocalIdentity(t *testing.T) {
	file, files := configFixture(t)
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	files["/config/config.json"] = data
	secretReads := 0
	loaded, err := loadConfig("/config/config.json", func(path string, maximum int64, secret bool) ([]byte, error) {
		if secret {
			secretReads++
			if path != file.IdentityKeyFile {
				t.Error("unexpected secret file")
			}
		} else if path == file.IdentityKeyFile {
			t.Error("key read without secret permissions")
		}
		b, ok := files[path]
		if !ok || int64(len(b)) > maximum {
			return nil, errors.New("fixture read rejected")
		}
		return bytes.Clone(b), nil
	})
	if err != nil || loaded == nil || secretReads != 1 {
		t.Fatalf("load=%v secret reads=%d", err, secretReads)
	}
	if !bytes.Equal(loaded.server.Identity.Certificate[0], loaded.control.Identity.Certificate[0]) || !bytes.Equal(loaded.server.Identity.Certificate[0], loaded.carrier.Identity.Certificate[0]) || loaded.server.ClockHealth == nil || loaded.server.Control != nil {
		t.Fatal("transport/inner identities or native health composition diverged")
	}
}

func TestConfigurationRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	file, files := configFixture(t)
	for _, name := range []string{"version", "workers", "device_limit", "timeout_overflow", "idle_limit", "public_control", "public_carrier", "missing_destinations", "missing_protection", "noncanonical_prefix", "unknown_field", "duplicate_field", "inline_health", "key_as_certificate", "wrong_key", "trailing_key", "trailing_certificate"} {
		t.Run(name, func(t *testing.T) {
			f := file
			switch name {
			case "version":
				f.Version = 0
			case "workers":
				f.Workers = 65
			case "device_limit":
				f.MaxDeviceSessions = f.Workers + 1
			case "timeout_overflow":
				f.OperationTimeoutMillis = 2147483647
			case "idle_limit":
				f.IdleTimeoutSeconds = 901
			case "public_control":
				f.Control.URL = "https://192.0.2.99:443"
			case "public_carrier":
				f.Carrier.URL = "https://example.test:443"
			case "missing_destinations":
				f.Destinations = nil
			case "missing_protection":
				f.ProtectedNetworks = nil
			case "noncanonical_prefix":
				f.ProtectedNetworks = []string{"10.99.0.1/16"}
			}
			data, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unknown_field":
				data = append([]byte(`{"extra":1,`), data[1:]...)
			case "duplicate_field":
				data = append([]byte(`{"VERSION":1,`), data[1:]...)
			case "inline_health":
				data = append([]byte(`{"clock_health_ms":20,`), data[1:]...)
			}
			loaded, err := loadConfig("/config/config.json", func(path string, _ int64, _ bool) ([]byte, error) {
				if path == "/config/config.json" {
					return data, nil
				}
				b := bytes.Clone(files[path])
				if path == f.IdentityKeyFile {
					switch name {
					case "key_as_certificate":
						b = bytes.Clone(files[f.IdentityCertificateFile])
					case "wrong_key":
						k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
						if e != nil {
							t.Fatal(e)
						}
						der, e := x509.MarshalPKCS8PrivateKey(k)
						if e != nil {
							t.Fatal(e)
						}
						b = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
					case "trailing_key":
						b = append(b, []byte("extra")...)
					}
				}
				if path == f.IdentityCertificateFile && name == "trailing_certificate" {
					b = append(b, b...)
				}
				return b, nil
			})
			if loaded != nil || !errors.Is(err, ErrConfiguration) {
				t.Fatalf("unsafe config accepted: %v", err)
			}
		})
	}
}
