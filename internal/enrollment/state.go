package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/google/uuid"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

const (
	stateVersion        = 1
	statePurpose        = "portico-ordinary-enrollment-attempt"
	certificatePurpose  = "portico-ordinary-enrollment-certificate"
	maxAttemptPlaintext = 8 * 1024
	maxAttemptFile      = 16 * 1024
	maxCertificateFile  = 32 * 1024
	scryptWorkFactor    = 18
)

// A single admitted KDF bounds concurrent memory use. There is no waiting queue
// or caller-controlled cost. The pinned age default is 2^18, also our read cap.
var stateKDF = make(chan struct{}, 1)

type stateBinding struct {
	Deployment, Issuer, Profile, Principal, Invitation string
	RootHash, IssuerHash                               string
	RedemptionURL, RedemptionRoot, RedemptionPin       string
	ActivationURL, ActivationRoot, ActivationPin       string
	NotAfter                                           int64
}

type attemptRecord struct {
	Version    int
	Purpose    string
	Binding    stateBinding
	AttemptID  string
	PrivateKey []byte
}

type certificateRecord struct {
	Version        int
	Purpose        string
	Binding        stateBinding
	AttemptID      string
	CertificateDER []byte
}

// Attempt owns a software P-256 signer whose encrypted state was committed
// before this handle was returned. The fields cannot be supplied by callers.
// The OS user and administrator remain trusted; this is not a hardware key.
// Go/age retain internal allocations, so no forensic-erasure claim is made.
type Attempt struct {
	path    string
	binding stateBinding
	id      string
	key     *ecdsa.PrivateKey
}

func bindingFor(c Config, invitation string) (stateBinding, error) {
	if !pki.ValidID(invitation) {
		return stateBinding{}, ErrRejected
	}
	// New validates public configuration only; it does not connect to a server.
	client, err := New(c)
	if err != nil {
		return stateBinding{}, ErrRejected
	}
	client.Close()
	return stateBinding{
		Deployment: c.Trust.DeploymentID(), Issuer: c.Trust.IssuerID(), Profile: string(c.Trust.Profile()),
		Principal: c.PrincipalID, Invitation: invitation, RootHash: c.Trust.RootFingerprint(), IssuerHash: c.Trust.IssuerFingerprint(),
		RedemptionURL: c.Redemption.URL, RedemptionRoot: pki.Hash(c.Redemption.ServerRootDER), RedemptionPin: strings.ToLower(c.Redemption.ServerSPKI),
		ActivationURL: c.Activation.URL, ActivationRoot: pki.Hash(c.Activation.ServerRootDER), ActivationPin: strings.ToLower(c.Activation.ServerSPKI), NotAfter: c.NotAfter.Unix(),
	}, nil
}

func validPassphrase(passphrase []byte) bool {
	return len(passphrase) >= 16 && len(passphrase) <= 1024 && utf8.Valid(passphrase) && !bytes.ContainsAny(passphrase, "\x00\r\n")
}

func encryptAttempt(plaintext, passphrase []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > maxAttemptPlaintext || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	select {
	case stateKDF <- struct{}{}:
	default:
		return nil, ErrRejected
	}
	defer func() { <-stateKDF }()
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, ErrRejected
	}
	recipient.SetWorkFactor(scryptWorkFactor)
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, ErrRejected
	}
	if n, err := w.Write(plaintext); err != nil || n != len(plaintext) || w.Close() != nil || encrypted.Len() > maxAttemptFile {
		return nil, ErrRejected
	}
	return encrypted.Bytes(), nil
}

func decryptAttempt(ciphertext, passphrase []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext) > maxAttemptFile || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	select {
	case stateKDF <- struct{}{}:
	default:
		return nil, ErrRejected
	}
	defer func() { <-stateKDF }()
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, ErrRejected
	}
	identity.SetMaxWorkFactor(scryptWorkFactor)
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, ErrRejected
	}
	// Consume through authenticated EOF before returning any plaintext. Reading
	// just the age header or an initial chunk does not authenticate a whole file.
	plaintext, err := io.ReadAll(io.LimitReader(r, maxAttemptPlaintext+1))
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxAttemptPlaintext {
		clear(plaintext)
		return nil, ErrRejected
	}
	return plaintext, nil
}

// CreateAttempt creates new state only. An existing name or ambiguous disk
// failure returns no signer. Explicitly OpenAttempt to reconcile; never remove
// state or generate another key/attempt as a network retry. The invitation
// bearer secret is deliberately not accepted or persisted by this API.
// The caller owns passphrase and must clear it after the call.
func CreateAttempt(path string, c Config, invitation string, passphrase []byte) (*Attempt, error) {
	if runtime.GOOS != "linux" || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	binding, err := bindingFor(c, invitation)
	if err != nil {
		return nil, ErrRejected
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrRejected
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(der)
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, ErrRejected
	}
	plaintext, err := json.Marshal(attemptRecord{Version: stateVersion, Purpose: statePurpose, Binding: binding, AttemptID: id.String(), PrivateKey: der})
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(plaintext)
	ciphertext, err := encryptAttempt(plaintext, passphrase)
	if err != nil || localfile.Create(path, ciphertext) != nil {
		return nil, ErrRejected
	}
	return &Attempt{path: path, binding: binding, id: id.String(), key: key}, nil
}

// OpenAttempt validates and flushes existing encrypted state before unlocking.
// The approved invitation configuration must be supplied independently; values
// from an encrypted file are never promoted into new trust or authority.
func OpenAttempt(path string, c Config, invitation string, passphrase []byte) (*Attempt, error) {
	if runtime.GOOS != "linux" || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	binding, err := bindingFor(c, invitation)
	if err != nil {
		return nil, ErrRejected
	}
	ciphertext, err := localfile.ReadDurable(path, maxAttemptFile)
	if err != nil {
		return nil, ErrRejected
	}
	plaintext, err := decryptAttempt(ciphertext, passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer clear(plaintext)
	a, err := decodeAttempt(plaintext, binding)
	if err != nil {
		return nil, ErrRejected
	}
	a.path = path
	return a, nil
}

func decodeAttempt(plaintext []byte, binding stateBinding) (*Attempt, error) {
	var record attemptRecord
	defer func() { clear(record.PrivateKey) }()
	if len(plaintext) > maxAttemptPlaintext || wire.Decode(plaintext, &record) != nil || record.Version != stateVersion || record.Purpose != statePurpose || record.Binding != binding || !pki.ValidID(record.AttemptID) || len(record.PrivateKey) == 0 || len(record.PrivateKey) > pki.MaxDER {
		return nil, ErrRejected
	}
	key, err := x509.ParsePKCS8PrivateKey(record.PrivateKey)
	p256, ok := key.(*ecdsa.PrivateKey)
	if err != nil || !ok || p256.Curve != elliptic.P256() {
		return nil, ErrRejected
	}
	// Require one canonical PKCS#8 record, excluding trailing/alternate encodings.
	canonical, err := x509.MarshalPKCS8PrivateKey(p256)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, record.PrivateKey) {
		return nil, ErrRejected
	}
	return &Attempt{binding: binding, id: record.AttemptID, key: p256}, nil
}

func (a *Attempt) matches(c *Client) bool {
	if a == nil || a.key == nil || a.path == "" || !pki.ValidID(a.id) || c == nil {
		return false
	}
	binding, err := bindingFor(c.config, a.binding.Invitation)
	return err == nil && binding == a.binding
}

// Redeem retains the exact public certificate durably before activation can be
// attempted. If its response or persistence fails, reopen the original attempt
// and retry explicitly with the invitation secret. Signing remains at most once
// at the issuer. Existing certificate state must match byte for byte.
func (a *Attempt) Redeem(ctx context.Context, c *Client, secret string) error {
	if !a.matches(c) {
		return ErrRejected
	}
	r, err := NewRequest(a.binding.Invitation, secret, a.id, a.key)
	if err != nil {
		return ErrRejected
	}
	identity, err := c.Redeem(ctx, r, a.key)
	if err != nil {
		return ErrRejected
	}
	record := certificateRecord{Version: stateVersion, Purpose: certificatePurpose, Binding: a.binding, AttemptID: a.id, CertificateDER: identity.Certificate[0]}
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxCertificateFile {
		return ErrRejected
	}
	path := a.path + ".certificate"
	// Regardless of Create's outcome, an identical existing record is accepted
	// only after validation and both durability barriers. Never overwrite it.
	_ = localfile.Create(path, data)
	stored, err := localfile.ReadDurable(path, maxCertificateFile)
	if err != nil || !bytes.Equal(data, stored) {
		return ErrRejected
	}
	return nil
}

// Certificate loads the retained public result and composes it with this local
// signer. It does not assert activation or current resource authorization.
func (a *Attempt) Certificate(c *Client) (tls.Certificate, error) {
	if !a.matches(c) {
		return tls.Certificate{}, ErrRejected
	}
	data, err := localfile.ReadDurable(a.path+".certificate", maxCertificateFile)
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	var record certificateRecord
	if wire.Decode(data, &record) != nil || record.Version != stateVersion || record.Purpose != certificatePurpose || record.Binding != a.binding || record.AttemptID != a.id {
		return tls.Certificate{}, ErrRejected
	}
	public, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	credential, err := c.config.Trust.Verify(record.CertificateDER, c.config.PrincipalID, time.Now())
	if err != nil || !credential.NotAfter.Equal(c.config.NotAfter) || credential.SPKISHA256 != pki.Hash(public) {
		return tls.Certificate{}, ErrRejected
	}
	identity, err := c.config.Trust.TLSIdentity(tls.Certificate{Certificate: [][]byte{record.CertificateDER}, PrivateKey: a.key})
	if err != nil {
		return tls.Certificate{}, ErrRejected
	}
	return identity, nil
}

// Activate can recover a lost activation response without an invitation secret
// by proving possession of the same key on fresh TLS. The server's live registry
// remains authoritative; no local active flag bypasses it.
func (a *Attempt) Activate(ctx context.Context, c *Client) error {
	identity, err := a.Certificate(c)
	if err != nil {
		return ErrRejected
	}
	return c.Activate(ctx, a.binding.Invitation, identity)
}
