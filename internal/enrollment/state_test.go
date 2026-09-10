package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func stateFixture(t *testing.T) (*clientFixture, stateBinding) {
	t.Helper()
	f := newClientFixture(t)
	f.config.Redemption = Endpoint{URL: "https://localhost:1", ServerRootDER: f.root.Raw, ServerSPKI: pki.Hash(f.serverIdentity.Leaf.RawSubjectPublicKeyInfo)}
	f.config.Activation = f.config.Redemption
	f.config.Activation.URL = "https://localhost:2"
	binding, err := bindingFor(f.config, f.request.InvitationID)
	testfixture.Must(t, err)
	return f, binding
}

func TestEncryptedAttemptAuthenticatesCompleteFile(t *testing.T) {
	passphrase := []byte("isolated test fixture passphrase")
	defer clear(passphrase)
	plaintext := []byte(`{"private":"fixture-only key bytes"}`)
	encrypted, err := encryptAttempt(plaintext, passphrase)
	testfixture.Must(t, err)
	if bytes.Contains(encrypted, plaintext) || !bytes.HasPrefix(encrypted, []byte("age-encryption.org/v1\n")) {
		t.Fatal("state was not age encrypted")
	}
	opened, err := decryptAttempt(encrypted, passphrase)
	testfixture.Must(t, err)
	defer clear(opened)
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("round trip changed state")
	}
	tampered := bytes.Clone(encrypted)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name             string
		data, passphrase []byte
	}{
		{"wrong_passphrase", encrypted, []byte("another isolated test passphrase")},
		{"tampered_final_tag", tampered, passphrase},
		{"truncated", encrypted[:len(encrypted)-1], passphrase},
		{"appended", append(bytes.Clone(encrypted), 0), passphrase},
		{"excessive_cost_header", bytes.Replace(encrypted, []byte(" 18\n"), []byte(" 30\n"), 1), passphrase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := decryptAttempt(tc.data, tc.passphrase)
			if data != nil || !errors.Is(err, ErrRejected) {
				t.Fatal("unauthenticated state returned plaintext")
			}
		})
	}
}

func TestAttemptKDFAdmissionAndInputBounds(t *testing.T) {
	passphrase := []byte("isolated test fixture passphrase")
	for _, invalid := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("a"), 1025), []byte("invalid passphrase\x00"), []byte("invalid passphrase\n"), append(bytes.Repeat([]byte("a"), 16), 0xff)} {
		if data, err := encryptAttempt([]byte("fixture"), invalid); data != nil || err != ErrRejected {
			t.Fatal("invalid passphrase accepted")
		}
		if data, err := decryptAttempt([]byte("fixture"), invalid); data != nil || err != ErrRejected {
			t.Fatal("invalid unlock input accepted")
		}
	}
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte("a"), maxAttemptPlaintext+1)} {
		if data, err := encryptAttempt(invalid, passphrase); data != nil || err != ErrRejected {
			t.Fatal("invalid plaintext bound accepted")
		}
	}
	if data, err := decryptAttempt(bytes.Repeat([]byte("a"), maxAttemptFile+1), passphrase); data != nil || err != ErrRejected {
		t.Fatal("invalid ciphertext bound accepted")
	}
	stateKDF <- struct{}{}
	defer func() { <-stateKDF }()
	if data, err := encryptAttempt([]byte("fixture"), passphrase); data != nil || err != ErrRejected {
		t.Fatal("encryption admitted while KDF occupied")
	}
	if data, err := decryptAttempt([]byte("fixture"), passphrase); data != nil || err != ErrRejected {
		t.Fatal("decryption admitted while KDF occupied")
	}
}

func TestAttemptRejectsChangedBindingAndMalformedKey(t *testing.T) {
	f, binding := stateFixture(t)
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	testfixture.Must(t, err)
	defer clear(der)
	record := attemptRecord{Version: stateVersion, Purpose: statePurpose, Binding: binding, AttemptID: f.request.AttemptID, PrivateKey: der}
	encode := func(r attemptRecord) []byte {
		data, err := json.Marshal(r)
		testfixture.Must(t, err)
		t.Cleanup(func() { clear(data) })
		return data
	}
	valid := encode(record)
	opened, err := decodeAttempt(valid, binding)
	testfixture.Must(t, err)
	if opened.id != record.AttemptID || !opened.key.PublicKey.Equal(&f.key.PublicKey) {
		t.Fatal("decoded attempt changed identity")
	}
	for _, change := range []struct {
		name  string
		apply func(*stateBinding)
	}{
		{"deployment", func(b *stateBinding) { b.Deployment = uuid.NewString() }},
		{"issuer", func(b *stateBinding) { b.Issuer = uuid.NewString() }},
		{"profile", func(b *stateBinding) { b.Profile = "administrator" }},
		{"principal", func(b *stateBinding) { b.Principal = uuid.NewString() }},
		{"invitation", func(b *stateBinding) { b.Invitation = uuid.NewString() }},
		{"root", func(b *stateBinding) { b.RootHash = strings.Repeat("0", 64) }},
		{"issuer_certificate", func(b *stateBinding) { b.IssuerHash = strings.Repeat("0", 64) }},
		{"redemption_url", func(b *stateBinding) { b.RedemptionURL = "https://localhost:3" }},
		{"redemption_root", func(b *stateBinding) { b.RedemptionRoot = strings.Repeat("0", 64) }},
		{"redemption_pin", func(b *stateBinding) { b.RedemptionPin = strings.Repeat("0", 64) }},
		{"activation_url", func(b *stateBinding) { b.ActivationURL = "https://localhost:3" }},
		{"activation_root", func(b *stateBinding) { b.ActivationRoot = strings.Repeat("0", 64) }},
		{"activation_pin", func(b *stateBinding) { b.ActivationPin = strings.Repeat("0", 64) }},
		{"expiry", func(b *stateBinding) { b.NotAfter++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := record
			change.apply(&changed.Binding)
			if a, err := decodeAttempt(encode(changed), binding); a != nil || err != ErrRejected {
				t.Fatal("changed authority accepted")
			}
		})
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	testfixture.Must(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	testfixture.Must(t, err)
	defer clear(p384DER)
	for _, change := range []struct {
		name  string
		apply func(*attemptRecord)
	}{
		{"version", func(r *attemptRecord) { r.Version++ }},
		{"purpose", func(r *attemptRecord) { r.Purpose = certificatePurpose }},
		{"attempt", func(r *attemptRecord) { r.AttemptID = "invalid" }},
		{"empty_key", func(r *attemptRecord) { r.PrivateKey = nil }},
		{"public_key", func(r *attemptRecord) { r.PrivateKey = f.identity.Certificate[0] }},
		{"non_p256", func(r *attemptRecord) { r.PrivateKey = p384DER }},
		{"trailing_key_data", func(r *attemptRecord) { r.PrivateKey = append(bytes.Clone(der), 0) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := record
			change.apply(&changed)
			if a, err := decodeAttempt(encode(changed), binding); a != nil || err != ErrRejected {
				t.Fatal("malformed state accepted")
			}
		})
	}
	for _, data := range [][]byte{[]byte(`{"Version":1,"version":1}`), []byte(`{"Unknown":true}`), []byte("[]"), append(bytes.Clone(valid), []byte("{}")...)} {
		if a, err := decodeAttempt(data, binding); a != nil || err != ErrRejected {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestAttemptRequiresApprovedConfiguration(t *testing.T) {
	f, _ := stateFixture(t)
	for _, change := range []func(*Config){
		func(c *Config) { c.Trust = nil },
		func(c *Config) { c.PrincipalID = "invalid" },
		func(c *Config) { c.NotAfter = time.Now().Add(-time.Minute) },
		func(c *Config) { c.Redemption.URL = "https://example.test:443" },
		func(c *Config) { c.Redemption.ServerSPKI = "" },
	} {
		c := f.config
		change(&c)
		if _, err := bindingFor(c, f.request.InvitationID); err != ErrRejected {
			t.Fatal("invalid approved configuration accepted")
		}
	}
	if _, err := bindingFor(f.config, ""); err != ErrRejected {
		t.Fatal("missing invitation accepted")
	}
	admin, err := pki.NewTrust(pki.Config{DeploymentID: f.config.Trust.DeploymentID(), IssuerID: f.config.Trust.IssuerID(), Profile: pki.Administrator, RootDER: f.root.Raw, IssuerDER: f.issuer.Raw})
	testfixture.Must(t, err)
	c := f.config
	c.Trust = admin
	if _, err := bindingFor(c, f.request.InvitationID); err != ErrRejected {
		t.Fatal("administrator state accepted")
	}
	if runtime.GOOS != "linux" {
		pass := []byte("isolated test fixture passphrase")
		if a, err := CreateAttempt("unused", f.config, f.request.InvitationID, pass); a != nil || err != ErrRejected {
			t.Fatal("unsupported platform created state")
		}
		if a, err := OpenAttempt("unused", f.config, f.request.InvitationID, pass); a != nil || err != ErrRejected {
			t.Fatal("unsupported platform opened state")
		}
	}
}
