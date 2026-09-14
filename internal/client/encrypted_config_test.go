package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"testing"

	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestEncryptedConfigurationUsesOneIdentityWithoutPlaintextFallback(t *testing.T) {
	legacy, files := configFixture(t)
	identity, err := tls.X509KeyPair(files[legacy.IdentityCertificateFile], files[legacy.IdentityKeyFile])
	testfixture.Must(t, err)
	file := legacy
	file.Version = 2
	file.IdentityCertificateFile = ""
	file.IdentityKeyFile = ""
	file.EnrollmentConfigFile = "/config/enrollment.json"
	var encoded []byte
	read := func(path string, maximum int64, secret bool) ([]byte, error) {
		if secret || path == legacy.IdentityKeyFile || path == legacy.IdentityCertificateFile {
			t.Fatal("encrypted configuration read a plaintext identity")
		}
		if path == "/config/client.json" {
			return bytes.Clone(encoded), nil
		}
		b, ok := files[path]
		if !ok || int64(len(b)) > maximum {
			return nil, errors.New("fixture input rejected")
		}
		return bytes.Clone(b), nil
	}
	encoded, err = json.Marshal(file)
	testfixture.Must(t, err)
	calls := 0
	unlock := func(path string, trust *pki.Trust) (tls.Certificate, error) {
		calls++
		if path != file.EnrollmentConfigFile || trust.Profile() != pki.Device || trust.DeploymentID() != file.DeploymentID || trust.IssuerID() != file.Devices.IssuerID {
			t.Fatal("unlock widened approved trust")
		}
		return identity, nil
	}
	loaded, err := loadConfigIdentity("/config/client.json", read, unlock)
	testfixture.Must(t, err)
	if calls != 1 || !bytes.Equal(loaded.workload.Identity.Certificate[0], identity.Certificate[0]) || !bytes.Equal(loaded.control.Identity.Certificate[0], identity.Certificate[0]) || !bytes.Equal(loaded.carrier.Identity.Certificate[0], identity.Certificate[0]) || loaded.workload.Identity.PrivateKey != loaded.control.Identity.PrivateKey || loaded.workload.Identity.PrivateKey != loaded.carrier.Identity.PrivateKey {
		t.Fatal("encrypted signer identity diverged")
	}
	if c, err := loadConfig("/config/client.json", read); c != nil || err != ErrConfiguration {
		t.Fatal("version 2 loaded without unlock")
	}
	for _, tc := range []struct {
		name   string
		change func(*FileConfig)
	}{
		{"legacy_mode", func(c *FileConfig) { c.Version = 1 }},
		{"unknown_version", func(c *FileConfig) { c.Version = 3 }},
		{"missing_enrollment", func(c *FileConfig) { c.EnrollmentConfigFile = "" }},
		{"plaintext_key", func(c *FileConfig) { c.IdentityKeyFile = legacy.IdentityKeyFile }},
		{"plaintext_certificate", func(c *FileConfig) { c.IdentityCertificateFile = legacy.IdentityCertificateFile }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := file
			tc.change(&mutated)
			encoded, err = json.Marshal(mutated)
			testfixture.Must(t, err)
			calls = 0
			if c, err := loadConfigIdentity("/config/client.json", read, unlock); c != nil || err != ErrConfiguration || calls != 0 {
				t.Fatal("invalid encrypted configuration reached unlock")
			}
		})
	}
	encoded, err = json.Marshal(file)
	testfixture.Must(t, err)
	for _, tc := range []struct {
		name     string
		identity tls.Certificate
		err      error
	}{
		{"unlock_failed", tls.Certificate{}, errors.New("synthetic private failure")},
		{"missing_key", tls.Certificate{Certificate: identity.Certificate}, nil},
		{"wrong_key", tls.Certificate{Certificate: identity.Certificate, PrivateKey: testfixture.Key(t)}, nil},
		{"missing_certificate", tls.Certificate{PrivateKey: identity.PrivateKey}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c, err := loadConfigIdentity("/config/client.json", read, func(string, *pki.Trust) (tls.Certificate, error) { return tc.identity, tc.err }); c != nil || err != ErrConfiguration {
				t.Fatal("invalid unlocked identity accepted or leaked details")
			}
		})
	}
	mutated := file
	mutated.Devices = file.Connectors
	encoded, err = json.Marshal(mutated)
	testfixture.Must(t, err)
	if c, err := loadConfigIdentity("/config/client.json", read, func(string, *pki.Trust) (tls.Certificate, error) { return identity, nil }); c != nil || err != ErrConfiguration {
		t.Fatal("device key accepted against connector trust")
	}
}
