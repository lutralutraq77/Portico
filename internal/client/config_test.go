package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	root, rootKey := testfixture.Root(t)
	files := map[string][]byte{}
	write := func(name, kind string, data []byte) string {
		path := "/config/" + name
		files[path] = pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data})
		return path
	}
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		testfixture.Must(t, e)
		return k
	}
	deviceKey, connectorKey, identityKey := key(), key(), key()
	now := time.Now()
	issuer := func(n int64, k *ecdsa.PrivateKey) *x509.Certificate {
		return testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &k.PublicKey, rootKey)
	}
	device, connector := issuer(2, deviceKey), issuer(3, connectorKey)
	uri, e := pki.IdentityURI(deployment, pki.Device, "9f61c38c-5b90-4581-8b87-5c54ffca9d0d")
	testfixture.Must(t, e)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(4), NotBefore: now.Add(-time.Second), NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, device, &identityKey.PublicKey, deviceKey)
	der, e := x509.MarshalPKCS8PrivateKey(identityKey)
	testfixture.Must(t, e)
	rootPath := write("root.pem", "CERTIFICATE", root.Raw)
	endpoint := EndpointFiles{URL: "https://localhost:8443", RootCertificateFile: rootPath, SPKI: pki.Hash(root.RawSubjectPublicKeyInfo)}
	file := FileConfig{Version: 1, DeploymentID: deployment, Devices: TrustFiles{IssuerID: "2846c6fd-bcef-453a-8b8e-13e681bf6004", RootCertificateFile: rootPath, IssuerCertificateFile: write("device.pem", "CERTIFICATE", device.Raw)}, Connectors: TrustFiles{IssuerID: "3aa6fcd1-e757-453d-8509-bc4c6d46761c", RootCertificateFile: rootPath, IssuerCertificateFile: write("connector.pem", "CERTIFICATE", connector.Raw)}, IdentityCertificateFile: write("identity.pem", "CERTIFICATE", leaf.Raw), IdentityKeyFile: write("key.pem", "PRIVATE KEY", der), Control: endpoint, Carrier: endpoint, OperationTimeoutMillis: 5000, IdleTimeoutSeconds: 60}
	return file, files
}

func TestConfigurationUsesOneProtectedDeviceIdentity(t *testing.T) {
	file, files := configFixture(t)
	data, e := json.Marshal(file)
	testfixture.Must(t, e)
	secretReads := 0
	loaded, e := loadConfig("/config/config.json", func(path string, limit int64, secret bool) ([]byte, error) {
		if path == "/config/config.json" {
			return data, nil
		}
		if secret {
			secretReads++
			if path != file.IdentityKeyFile {
				t.Fatal("wrong secret file")
			}
		}
		if path == file.IdentityKeyFile && !secret {
			t.Fatal("unprotected key read")
		}
		b, ok := files[path]
		if !ok || int64(len(b)) > limit {
			return nil, errors.New("fixture input rejected")
		}
		return bytes.Clone(b), nil
	})
	testfixture.Must(t, e)
	if secretReads != 1 || loaded.workload.Devices.Profile() != pki.Device || loaded.workload.Control != nil || loaded.workload.ClockHealth == nil || loaded.workload.MaxConnections != 1 || loaded.control.Profile != pki.Device || !bytes.Equal(loaded.workload.Identity.Certificate[0], loaded.control.Identity.Certificate[0]) || !bytes.Equal(loaded.workload.Identity.Certificate[0], loaded.carrier.Identity.Certificate[0]) {
		t.Fatal("client identity/security composition diverged")
	}
}

func TestConfigurationRejectsOverridesAndUnsafeIdentity(t *testing.T) {
	file, files := configFixture(t)
	for _, name := range []string{"version", "timeout", "idle", "public_control", "public_carrier", "identity_role", "unknown", "duplicate", "username", "destination", "clock_override", "inline_key", "wrong_key", "trailing_key", "trailing_certificate"} {
		t.Run(name, func(t *testing.T) {
			f := file
			switch name {
			case "version":
				f.Version = 2
			case "timeout":
				f.OperationTimeoutMillis = 2147483647
			case "idle":
				f.IdleTimeoutSeconds = 901
			case "public_control":
				f.Control.URL = "https://192.0.2.99:443"
			case "public_carrier":
				f.Carrier.URL = "https://outside.test:443"
			case "identity_role":
				f.Devices = f.Connectors
			}
			data, e := json.Marshal(f)
			testfixture.Must(t, e)
			extra := map[string]string{"unknown": `"extra":1,`, "duplicate": `"VERSION":1,`, "username": `"username":"owner",`, "destination": `"address":"192.0.2.10",`, "clock_override": `"clock_health_ms":0,`, "inline_key": `"private_key":"fixture-private-canary",`}[name]
			if extra != "" {
				data = append([]byte("{"+extra), data[1:]...)
			}
			loaded, e := loadConfig("/config/config.json", func(path string, _ int64, _ bool) ([]byte, error) {
				if path == "/config/config.json" {
					return data, nil
				}
				b := bytes.Clone(files[path])
				if path == f.IdentityKeyFile {
					if name == "wrong_key" {
						b = bytes.Clone(files[f.IdentityCertificateFile])
					}
					if name == "trailing_key" {
						b = append(b, []byte("fixture-private-canary")...)
					}
				}
				if path == f.IdentityCertificateFile && name == "trailing_certificate" {
					b = append(b, b...)
				}
				return b, nil
			})
			if loaded != nil || e != ErrConfiguration {
				t.Fatal("unsafe client configuration accepted")
			}
		})
	}
}
