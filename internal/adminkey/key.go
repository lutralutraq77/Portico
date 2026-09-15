// Package adminkey retains an administrator device signer in encrypted Linux
// storage. A key file supplies no new trust, enrollment or server authority.
package adminkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

var ErrRejected = errors.New("administrator key rejected")

const (
	purpose       = "portico-administrator-device-key"
	maxPlaintext  = 8192
	maxCiphertext = 16384
	workFactor    = 18
)

// Bound expensive work to one operation, without a queue or configurable cost.
var kdf = make(chan struct{}, 1)

type binding struct {
	Deployment, Issuer, Profile, Principal, RootHash, IssuerHash string
}

type record struct {
	Version    int
	Purpose    string
	Binding    binding
	PrivateKey []byte
}

// Key implements crypto.Signer without exporting private material. Closing it
// disables signatures through every previously returned TLS identity. The
// trusted OS user and administrator can access process memory; this is software
// custody, not hardware isolation or a promise of forensic memory erasure.
type Key struct {
	mu        sync.Mutex
	private   *ecdsa.PrivateKey
	trust     *pki.Trust
	principal string
}

func bindingFor(trust *pki.Trust, principal string) (binding, error) {
	if trust == nil || trust.Profile() != pki.Administrator || !pki.ValidID(principal) || !time.Now().Before(trust.NotAfter()) {
		return binding{}, ErrRejected
	}
	return binding{trust.DeploymentID(), trust.IssuerID(), string(trust.Profile()), principal, trust.RootFingerprint(), trust.IssuerFingerprint()}, nil
}

func validPassphrase(passphrase []byte) bool {
	return len(passphrase) >= 16 && len(passphrase) <= 1024 && utf8.Valid(passphrase) && !bytes.ContainsAny(passphrase, "\x00\r\n")
}

func seal(plaintext, passphrase []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > maxPlaintext || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	select {
	case kdf <- struct{}{}:
	default:
		return nil, ErrRejected
	}
	defer func() { <-kdf }()
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, ErrRejected
	}
	recipient.SetWorkFactor(workFactor)
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, ErrRejected
	}
	if n, err := w.Write(plaintext); err != nil || n != len(plaintext) || w.Close() != nil || ciphertext.Len() > maxCiphertext {
		return nil, ErrRejected
	}
	return ciphertext.Bytes(), nil
}

func unseal(ciphertext, passphrase []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext) > maxCiphertext || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	select {
	case kdf <- struct{}{}:
	default:
		return nil, ErrRejected
	}
	defer func() { <-kdf }()
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, ErrRejected
	}
	identity.SetMaxWorkFactor(workFactor)
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, ErrRejected
	}
	// No plaintext leaves this function until authenticated EOF is consumed.
	plaintext, err := io.ReadAll(io.LimitReader(r, maxPlaintext+1))
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		clear(plaintext)
		return nil, ErrRejected
	}
	return plaintext, nil
}

// Create generates a new P-256 key and commits encrypted state before exposing
// its signer. The caller independently supplies approved administrator trust.
// Existing files are never replaced; an ambiguous durability error returns no
// signer. Reconcile by Open on the same file, without deleting or regenerating
// it as a network retry. The caller owns and must clear its passphrase buffer.
func Create(path string, trust *pki.Trust, principal string, passphrase []byte) (*Key, error) {
	if runtime.GOOS != "linux" || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	b, err := bindingFor(trust, principal)
	if err != nil {
		return nil, ErrRejected
	}
	parent, _, err := localfile.OpenPrivateParent(path)
	if err != nil {
		return nil, ErrRejected
	}
	_ = parent.Close()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrRejected
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(der)
	plaintext, err := json.Marshal(record{1, purpose, b, der})
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(plaintext)
	ciphertext, err := seal(plaintext, passphrase)
	if err != nil || localfile.Create(path, ciphertext) != nil {
		return nil, ErrRejected
	}
	return &Key{private: private, trust: trust, principal: principal}, nil
}

// Open validates ownership, permissions, durability, the complete ciphertext
// and its purpose/profile/deployment/issuer/principal binding before unlocking.
// The encrypted file cannot override any independently supplied trust field.
func Open(path string, trust *pki.Trust, principal string, passphrase []byte) (*Key, error) {
	if runtime.GOOS != "linux" || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	b, err := bindingFor(trust, principal)
	if err != nil {
		return nil, ErrRejected
	}
	parent, _, err := localfile.OpenPrivateParent(path)
	if err != nil {
		return nil, ErrRejected
	}
	_ = parent.Close()
	ciphertext, err := localfile.ReadDurable(path, maxCiphertext)
	if err != nil {
		return nil, ErrRejected
	}
	plaintext, err := unseal(ciphertext, passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(plaintext)
	return decode(plaintext, b, trust)
}

func decode(plaintext []byte, expected binding, trust *pki.Trust) (*Key, error) {
	var r record
	defer func() { clear(r.PrivateKey) }()
	if len(plaintext) == 0 || len(plaintext) > maxPlaintext || wire.Decode(plaintext, &r) != nil || r.Version != 1 || r.Purpose != purpose || r.Binding != expected || len(r.PrivateKey) == 0 || len(r.PrivateKey) > pki.MaxDER {
		return nil, ErrRejected
	}
	parsed, err := x509.ParsePKCS8PrivateKey(r.PrivateKey)
	private, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || private.Curve != elliptic.P256() {
		return nil, ErrRejected
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(private)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, r.PrivateKey) {
		return nil, ErrRejected
	}
	return &Key{private: private, trust: trust, principal: expected.Principal}, nil
}

func (k *Key) Close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.private = nil
}

func (k *Key) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.private == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(&k.private.PublicKey)
	if err != nil {
		return nil
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil
	}
	return public
}

func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, ErrRejected
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.private == nil || k.trust == nil || !time.Now().Before(k.trust.NotAfter()) {
		return nil, ErrRejected
	}
	// Entropy comes from the OS, not a reader supplied through another caller.
	return k.private.Sign(rand.Reader, digest, opts)
}

// CSR supplies proof of possession only. The approved server-side operation
// supplies identity, validity and extensions; no caller claims are signed.
func (k *Key) CSR() ([]byte, error) {
	if k == nil || k.Public() == nil {
		return nil, ErrRejected
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}, k)
	if err != nil {
		return nil, ErrRejected
	}
	if _, err := pki.ParseCSR(der); err != nil {
		return nil, ErrRejected
	}
	return der, nil
}

// Identity combines a verified public certificate with this revocable signer.
// Current registry status, native session expiry and hardware-key approval are
// enforced by the transport/controller, not inferred from local key storage.
func (k *Key) Identity(leaf []byte) (tls.Certificate, error) {
	if k == nil || k.trust == nil {
		return tls.Certificate{}, ErrRejected
	}
	if _, err := k.trust.Verify(leaf, k.principal, time.Now()); err != nil {
		return tls.Certificate{}, ErrRejected
	}
	identity, err := k.trust.TLSIdentity(tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: k})
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	return identity, nil
}
