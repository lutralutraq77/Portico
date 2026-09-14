package adminapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func fixture(t *testing.T) (FileConfig, map[string][]byte, tls.Certificate, func(crypto.PublicKey) []byte) {
	t.Helper()
	base := t.TempDir()
	root, rootKey := testfixture.Root(t)
	issuerKey, key := testfixture.Key(t), testfixture.Key(t)
	now := time.Now()
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, issuerKey.Public(), rootKey)
	f := FileConfig{Version: 1, DeploymentID: uuid.NewString(), PrincipalID: uuid.NewString(), EncryptedKeyFile: filepath.Join(base, "key.age"), StateDirectory: filepath.Join(base, "state"), BootstrapAddress: "127.0.0.1:8443", OperationTimeoutMillis: 5000, SessionLifetimeSeconds: 60}
	uri, err := pki.IdentityURI(f.DeploymentID, pki.Administrator, f.PrincipalID)
	testfixture.Must(t, err)
	leaf := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, issuer, key.Public(), issuerKey)
	files := make(map[string][]byte)
	write := func(name string, der []byte) string {
		path := filepath.Join(base, name)
		files[path] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return path
	}
	f.Administrators = identityfile.TrustFiles{IssuerID: uuid.NewString(), RootCertificateFile: write("root.pem", root.Raw), IssuerCertificateFile: write("issuer.pem", issuer.Raw)}
	f.IdentityCertificateFile = write("leaf.pem", leaf.Raw)
	f.Server = identityfile.EndpointFiles{URL: "https://admin.test", RootCertificateFile: f.Administrators.RootCertificateFile, SPKI: pki.Hash(root.RawSubjectPublicKeyInfo)}
	issue := func(public crypto.PublicKey) []byte {
		template := *leaf
		template.SerialNumber = big.NewInt(4)
		return testfixture.Certificate(t, &template, issuer, public, issuerKey).Raw
	}
	return f, files, tls.Certificate{Certificate: [][]byte{leaf.Raw, issuer.Raw}, PrivateKey: key, Leaf: leaf}, issue
}

func loadFixture(t *testing.T, data []byte, files map[string][]byte) (*Configuration, error) {
	t.Helper()
	return load("fixture-config", func(path string, limit int64, secret bool) ([]byte, error) {
		if secret {
			t.Fatal("configuration attempted plaintext secret access")
		}
		if path == "fixture-config" {
			return bytes.Clone(data), nil
		}
		value, ok := files[path]
		if !ok || int64(len(value)) > limit {
			return nil, ErrRejected
		}
		return bytes.Clone(value), nil
	})
}

func TestProtectedConfigurationBindsAdministrator(t *testing.T) {
	f, files, _, _ := fixture(t)
	for _, socket := range []bool{false, true} {
		if socket {
			f.BootstrapAddress = ""
			f.Socket = filepath.Join(filepath.Dir(f.StateDirectory), "management.sock")
		}
		data, err := json.Marshal(f)
		testfixture.Must(t, err)
		c, err := loadFixture(t, data, files)
		testfixture.Must(t, err)
		if c.bridge.AdministratorTrust.Profile() != pki.Administrator || c.bridge.Origin != f.Server.URL || c.principal != f.PrincipalID || c.keyPath != f.EncryptedKeyFile || c.bridge.Identity.PrivateKey != nil || c.bridge.ClockHealth != nil || c.bridge.Socket != f.Socket || c.bridge.BootstrapAddress != f.BootstrapAddress {
			t.Fatal("configuration changed administrator authority or loaded a signer")
		}
	}
}

func TestConfigurationRejectsAuthorityAndLaunchOverrides(t *testing.T) {
	f, files, _, _ := fixture(t)
	changes := map[string]func(*FileConfig){
		"version":           func(f *FileConfig) { f.Version = 2 },
		"deployment":        func(f *FileConfig) { f.DeploymentID = uuid.NewString() },
		"principal":         func(f *FileConfig) { f.PrincipalID = uuid.NewString() },
		"missing_principal": func(f *FileConfig) { f.PrincipalID = "" },
		"issuer":            func(f *FileConfig) { f.Administrators.IssuerCertificateFile = f.Administrators.RootCertificateFile },
		"leaf_as_root":      func(f *FileConfig) { f.Server.RootCertificateFile = f.IdentityCertificateFile },
		"origin":            func(f *FileConfig) { f.Server.URL += "/admin" },
		"pin":               func(f *FileConfig) { f.Server.SPKI = strings.ToUpper(f.Server.SPKI) },
		"short_pin":         func(f *FileConfig) { f.Server.SPKI = "00" },
		"public_bootstrap":  func(f *FileConfig) { f.BootstrapAddress = "192.0.2.1:8443" },
		"bootstrap_dns":     func(f *FileConfig) { f.BootstrapAddress = "localhost:8443" },
		"both_routes":       func(f *FileConfig) { f.Socket = f.StateDirectory },
		"no_route":          func(f *FileConfig) { f.BootstrapAddress = "" },
		"relative_socket":   func(f *FileConfig) { f.BootstrapAddress = ""; f.Socket = "relative.sock" },
		"relative_key":      func(f *FileConfig) { f.EncryptedKeyFile = "key.age" },
		"relative_state":    func(f *FileConfig) { f.StateDirectory = "state" },
		"long_request":      func(f *FileConfig) { f.OperationTimeoutMillis = 5001 },
		"no_timeout":        func(f *FileConfig) { f.OperationTimeoutMillis = 0 },
		"long_session":      func(f *FileConfig) { f.SessionLifetimeSeconds = 601 },
		"no_lifetime":       func(f *FileConfig) { f.SessionLifetimeSeconds = 0 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			modified := f
			change(&modified)
			data, err := json.Marshal(modified)
			testfixture.Must(t, err)
			if c, err := loadFixture(t, data, files); c != nil || err != ErrRejected {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	data, err := json.Marshal(f)
	testfixture.Must(t, err)
	for _, extra := range []string{`"version":1`, `"identity_key_file":"plaintext"`, `"executable":"arbitrary"`, `"clock_health":0`, `"arguments":[]`, `"environment":{}`, `"allow_insecure":true`} {
		t.Run(extra, func(t *testing.T) {
			modified := append(bytes.Clone(data[:len(data)-1]), []byte(","+extra+"}")...)
			if c, err := loadFixture(t, modified, files); c != nil || err != ErrRejected {
				t.Fatal("unknown or duplicate field accepted")
			}
		})
	}
}

type lifecycleKey struct {
	identity    tls.Certificate
	identityErr error
	close       func()
}

func (k *lifecycleKey) Identity([]byte) (tls.Certificate, error) { return k.identity, k.identityErr }
func (k *lifecycleKey) Close()                                   { k.close() }

func TestSessionReleasesSignerAndStateOnEveryExit(t *testing.T) {
	for _, name := range []string{"success", "prepare_failure", "open_failure", "cancel_during_unlock", "identity_failure", "clock_failure", "window_failure", "cancel_in_window"} {
		t.Run(name, func(t *testing.T) {
			f, files, identity, _ := fixture(t)
			data, err := json.Marshal(f)
			testfixture.Must(t, err)
			c, err := loadFixture(t, data, files)
			testfixture.Must(t, err)
			c.bridge.ClockHealth = func() (time.Duration, error) {
				if name == "clock_failure" {
					return 0, ErrRejected
				}
				return time.Millisecond, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pass := []byte("isolated test passphrase")
			opened, closed, released, ran := 0, 0, 0, 0
			var bridge *adminbridge.Client
			prepare := func(state string) (adminbridge.Launch, func(), error) {
				if state != f.StateDirectory {
					t.Fatal("wrong private state")
				}
				if name == "prepare_failure" {
					return adminbridge.Launch{}, nil, ErrRejected
				}
				return adminbridge.Launch{}, func() {
					released++
					if closed != opened {
						t.Error("state released before signer was closed")
					}
				}, nil
			}
			open := func(path string, trust *pki.Trust, principal string, secret []byte) (deviceKey, error) {
				opened++
				if path != f.EncryptedKeyFile || trust.Profile() != pki.Administrator || principal != f.PrincipalID || string(secret) != "isolated test passphrase" {
					t.Fatal("unlock binding changed")
				}
				key := &lifecycleKey{identity: identity, close: func() {
					closed++
					if bridge != nil {
						select {
						case <-bridge.Done():
						default:
							t.Error("signer closed before bridge cancellation")
						}
					}
				}}
				if name == "cancel_during_unlock" {
					cancel()
				}
				if name == "identity_failure" {
					key.identityErr = ErrRejected
				}
				if name == "open_failure" {
					return key, ErrRejected
				}
				return key, nil
			}
			window := func(_ context.Context, b *adminbridge.Client, _ adminbridge.Launch) error {
				ran++
				bridge = b
				if closed != 0 || released != 0 || !bytes.Equal(pass, make([]byte, len(pass))) {
					t.Error("wrong key, passphrase or state lifetime")
				}
				if name == "cancel_in_window" {
					cancel()
				}
				if name == "window_failure" {
					return ErrRejected
				}
				return nil
			}
			err = c.run(ctx, pass, open, prepare, window)
			if (err == nil) != (name == "success") || closed != opened || !bytes.Equal(pass, make([]byte, len(pass))) {
				t.Fatal("unexpected outcome or retained secret")
			}
			wantRelease := 1
			if name == "prepare_failure" {
				wantRelease = 0
			}
			wantRun := 0
			if name == "success" || name == "window_failure" || name == "cancel_in_window" {
				wantRun = 1
			}
			if released != wantRelease || ran != wantRun {
				t.Fatal("window launched after failed check or state retained")
			}
		})
	}
}
