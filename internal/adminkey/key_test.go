package adminkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

type keyFixture struct {
	trust              *pki.Trust
	root, issuer       *x509.Certificate
	issuerKey, private *ecdsa.PrivateKey
	principal          string
}

func keySeed(t *testing.T) *keyFixture {
	t.Helper()
	root, rootKey := testfixture.Root(t)
	issuerKey := testfixture.Key(t)
	issuer := testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "isolated administrator issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root, &issuerKey.PublicKey, rootKey)
	trust, err := pki.NewTrust(pki.Config{DeploymentID: uuid.NewString(), IssuerID: uuid.NewString(), Profile: pki.Administrator, RootDER: root.Raw, IssuerDER: issuer.Raw})
	testfixture.Must(t, err)
	return &keyFixture{trust: trust, root: root, issuer: issuer, issuerKey: issuerKey, private: testfixture.Key(t), principal: uuid.NewString()}
}

func (f *keyFixture) key() *Key {
	return &Key{private: f.private, trust: f.trust, principal: f.principal}
}

func (f *keyFixture) leaf(t *testing.T, public crypto.PublicKey, principal string, profile pki.Profile) []byte {
	t.Helper()
	u, err := pki.IdentityURI(f.trust.DeploymentID(), profile, principal)
	testfixture.Must(t, err)
	return testfixture.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, f.issuer, public, f.issuerKey).Raw
}

func TestSignerIdentityAndClose(t *testing.T) {
	f := keySeed(t)
	k := f.key()
	t.Cleanup(k.Close)
	csrDER, err := k.CSR()
	testfixture.Must(t, err)
	csr, err := pki.ParseCSR(csrDER)
	testfixture.Must(t, err)
	if !f.private.PublicKey.Equal(csr.PublicKey) {
		t.Fatal("CSR changed key or carried caller authority")
	}
	leaf := f.leaf(t, csr.PublicKey, f.principal, pki.Administrator)
	identity, err := k.Identity(leaf)
	testfixture.Must(t, err)
	signer, ok := identity.PrivateKey.(crypto.Signer)
	if !ok || signer != k {
		t.Fatal("TLS identity bypasses revocable signer")
	}
	digest := sha256.Sum256([]byte("isolated fixture transcript"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	testfixture.Must(t, err)
	if !ecdsa.VerifyASN1(&f.private.PublicKey, digest[:], signature) {
		t.Fatal("invalid device signature")
	}
	public := k.Public().(*ecdsa.PublicKey)
	*public = *testfixture.Key(t).Public().(*ecdsa.PublicKey)
	if !f.private.PublicKey.Equal(k.Public()) {
		t.Fatal("caller mutated retained key through public view")
	}
	for _, leaf := range [][]byte{
		f.leaf(t, k.Public(), uuid.NewString(), pki.Administrator),
		f.leaf(t, k.Public(), f.principal, pki.Device),
		f.leaf(t, testfixture.Key(t).Public(), f.principal, pki.Administrator),
		nil,
	} {
		if _, err := k.Identity(leaf); err != ErrRejected {
			t.Fatal("unbound certificate accepted")
		}
	}
	if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA384); err != ErrRejected {
		t.Fatal("unexpected signing algorithm accepted")
	}
	if _, err := k.Sign(rand.Reader, digest[:31], crypto.SHA256); err != ErrRejected {
		t.Fatal("invalid digest accepted")
	}
	if _, err := k.Sign(rand.Reader, digest[:], nil); err != ErrRejected {
		t.Fatal("missing signing options accepted")
	}
	k.Close()
	k.Close()
	if k.Public() != nil {
		t.Fatal("closed handle retained key access")
	}
	if _, err := k.CSR(); err != ErrRejected {
		t.Fatal("closed handle created CSR")
	}
	if _, err := k.Identity(leaf); err != ErrRejected {
		t.Fatal("closed handle created TLS identity")
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != ErrRejected {
		t.Fatal("previous TLS identity signed after close")
	}
	var missing *Key
	missing.Close()
	if missing.Public() != nil {
		t.Fatal("nil key has public material")
	}
	if _, err := missing.Sign(rand.Reader, digest[:], crypto.SHA256); err != ErrRejected {
		t.Fatal("nil key signed")
	}
}

func TestConcurrentCloseRevokesRetainedIdentities(t *testing.T) {
	f := keySeed(t)
	k := f.key()
	identity, err := k.Identity(f.leaf(t, k.Public(), f.principal, pki.Administrator))
	testfixture.Must(t, err)
	signer := identity.PrivateKey.(crypto.Signer)
	digest := sha256.Sum256([]byte("isolated concurrent transcript"))
	var workers sync.WaitGroup
	ready := make(chan struct{}, 8)
	stop := make(chan struct{})
	for range 8 {
		workers.Go(func() {
			if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
				t.Error("live signer rejected initial concurrent use")
			}
			ready <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil && err != ErrRejected {
					t.Error("unexpected signer failure")
				}
			}
		})
	}
	for range 8 {
		<-ready
	}
	k.Close()
	close(stop)
	workers.Wait()
	for range 10 {
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != ErrRejected {
			t.Fatal("closed signer regained authority")
		}
	}
}

func TestEncryptedKeyAuthenticatesEntireFile(t *testing.T) {
	pass := []byte("isolated administrator storage fixture")
	defer clear(pass)
	plain := []byte(`{"fixture":"private bytes"}`)
	ciphertext, err := seal(plain, pass)
	testfixture.Must(t, err)
	if bytes.Contains(ciphertext, plain) || !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
		t.Fatal("private state persisted without age encryption")
	}
	opened, err := unseal(ciphertext, pass)
	testfixture.Must(t, err)
	defer clear(opened)
	if !bytes.Equal(opened, plain) {
		t.Fatal("authenticated state changed")
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	for _, scenario := range []struct {
		name       string
		data, pass []byte
	}{
		{"wrong_passphrase", ciphertext, []byte("different isolated administrator fixture")},
		{"final_tag", tampered, pass},
		{"truncated", ciphertext[:len(ciphertext)-1], pass},
		{"appended", append(bytes.Clone(ciphertext), 0), pass},
		{"excessive_cost", bytes.Replace(ciphertext, []byte(" 18\n"), []byte(" 30\n"), 1), pass},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if data, err := unseal(scenario.data, scenario.pass); data != nil || err != ErrRejected {
				t.Fatal("unauthenticated plaintext exposed")
			}
		})
	}
}

func TestKeyInputAndKDFBounds(t *testing.T) {
	pass := []byte("isolated administrator storage fixture")
	for _, invalid := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("x"), 1025), []byte("invalid administrator\x00"), []byte("invalid administrator\r"), []byte("invalid administrator\n"), append(bytes.Repeat([]byte("x"), 16), 255)} {
		if data, err := seal([]byte("fixture"), invalid); data != nil || err != ErrRejected {
			t.Fatal("invalid passphrase accepted for storage")
		}
		if data, err := unseal([]byte("fixture"), invalid); data != nil || err != ErrRejected {
			t.Fatal("invalid passphrase accepted for unlock")
		}
	}
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte("x"), maxPlaintext+1)} {
		if data, err := seal(invalid, pass); data != nil || err != ErrRejected {
			t.Fatal("plaintext bound exceeded")
		}
	}
	if data, err := unseal(bytes.Repeat([]byte("x"), maxCiphertext+1), pass); data != nil || err != ErrRejected {
		t.Fatal("ciphertext bound exceeded")
	}
	kdf <- struct{}{}
	defer func() { <-kdf }()
	if data, err := seal([]byte("fixture"), pass); data != nil || err != ErrRejected {
		t.Fatal("concurrent KDF admitted")
	}
	if data, err := unseal([]byte("fixture"), pass); data != nil || err != ErrRejected {
		t.Fatal("concurrent KDF admitted")
	}
}

func TestKeyRejectsSubstitutedAuthorityAndEncoding(t *testing.T) {
	f := keySeed(t)
	b, err := bindingFor(f.trust, f.principal)
	testfixture.Must(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(f.private)
	testfixture.Must(t, err)
	defer clear(der)
	original := record{1, purpose, b, der}
	encode := func(r record) []byte {
		data, err := json.Marshal(r)
		testfixture.Must(t, err)
		t.Cleanup(func() { clear(data) })
		return data
	}
	valid := encode(original)
	k, err := decode(valid, b, f.trust)
	testfixture.Must(t, err)
	t.Cleanup(k.Close)
	if !f.private.PublicKey.Equal(k.Public()) {
		t.Fatal("stored key changed")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	testfixture.Must(t, err)
	otherDER, err := x509.MarshalPKCS8PrivateKey(p384)
	testfixture.Must(t, err)
	defer clear(otherDER)
	for _, scenario := range []string{"version", "ordinary_purpose", "deployment", "issuer", "profile", "principal", "root", "issuer_certificate", "no_key", "wrong_curve", "trailing_key"} {
		t.Run(scenario, func(t *testing.T) {
			r := original
			switch scenario {
			case "version":
				r.Version++
			case "ordinary_purpose":
				r.Purpose = "portico-ordinary-enrollment-attempt"
			case "deployment":
				r.Binding.Deployment = uuid.NewString()
			case "issuer":
				r.Binding.Issuer = uuid.NewString()
			case "profile":
				r.Binding.Profile = string(pki.Device)
			case "principal":
				r.Binding.Principal = uuid.NewString()
			case "root":
				r.Binding.RootHash = "substituted"
			case "issuer_certificate":
				r.Binding.IssuerHash = "substituted"
			case "no_key":
				r.PrivateKey = nil
			case "wrong_curve":
				r.PrivateKey = otherDER
			case "trailing_key":
				r.PrivateKey = append(bytes.Clone(der), 0)
			}
			if k, err := decode(encode(r), b, f.trust); k != nil || err != ErrRejected {
				t.Fatal("substituted administrator key state accepted")
			}
		})
	}
	for _, data := range [][]byte{nil, []byte(`{"Version":1,"version":1}`), []byte(`{"Unknown":true}`), []byte("[]"), append(bytes.Clone(valid), []byte("{}")...)} {
		if k, err := decode(data, b, f.trust); k != nil || err != ErrRejected {
			t.Fatal("ambiguous key state accepted")
		}
	}
	if _, err := bindingFor(nil, f.principal); err != ErrRejected {
		t.Fatal("missing trust accepted")
	}
	if _, err := bindingFor(f.trust, "invalid"); err != ErrRejected {
		t.Fatal("invalid principal accepted")
	}
	ordinary, err := pki.NewTrust(pki.Config{DeploymentID: f.trust.DeploymentID(), IssuerID: f.trust.IssuerID(), Profile: pki.Device, RootDER: f.root.Raw, IssuerDER: f.issuer.Raw})
	testfixture.Must(t, err)
	if _, err := bindingFor(ordinary, f.principal); err != ErrRejected {
		t.Fatal("ordinary trust accepted for administrator state")
	}
	if runtime.GOOS != "linux" {
		pass := []byte("isolated administrator storage fixture")
		if k, err := Create("unused", f.trust, f.principal, pass); k != nil || err != ErrRejected {
			t.Fatal("unqualified platform created state")
		}
		if k, err := Open("unused", f.trust, f.principal, pass); k != nil || err != ErrRejected {
			t.Fatal("unqualified platform opened state")
		}
	}
}
