// Package adminauth verifies the hardware factor in an operation-bound ceremony.
// It does not establish the independent administrator device factor. Callers
// must derive Binding from their authenticated transport, keep sessions on the
// server, and consume successful results atomically with the exact operation.
package adminauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"portico.local/portico/internal/pki"
)

var ErrDenied = errors.New("administrator factor rejected")

const MaxResponse = 64 * 1024

func fmtAAGUID(b []byte) string {
	u, e := uuid.FromBytes(b)
	if e != nil {
		return ""
	}
	return u.String()
}
func decodeAttestation(b []byte, a *protocol.AttestationObject) error {
	return webauthncbor.Unmarshal(b, a)
}

// Model trust is local reviewed policy, not browser-supplied metadata. Only
// packed certificate attestation is supported initially. AAGUID alone, an
// attachment hint, or two credential IDs never proves independent hardware.
type Model struct {
	AAGUID   string
	RootsDER [][]byte
}
type Config struct {
	Origin     string
	Models     []Model
	ValidUntil time.Time
}
type Verifier struct {
	wa         *webauthn.WebAuthn
	origin     string
	roots      map[string]*x509.CertPool
	validUntil time.Time
	policyHash string
}

func (v *Verifier) Origin() string { return v.origin }

type User struct {
	ID          string
	Credentials []webauthn.Credential
}

func (u User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u User) WebAuthnName() string                       { return u.ID }
func (u User) WebAuthnDisplayName() string                { return "Portico administrator" }
func (u User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type Binding struct {
	AdministratorID       string
	DeviceCertificateHash string
	OperationHash         string
	Revision              int64
}
type Session struct {
	Binding              Binding
	PolicyHash           string
	Kind                 string
	CreatedAt, ExpiresAt time.Time
	Data                 webauthn.SessionData
}

func New(c Config) (*Verifier, error) {
	u, e := url.Parse(c.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host != strings.ToLower(u.Host) || net.ParseIP(u.Hostname()) != nil || !strings.Contains(u.Hostname(), ".") || len(c.Models) == 0 || len(c.Models) > 16 || !c.ValidUntil.After(time.Now()) || c.ValidUntil.After(time.Now().Add(90*24*time.Hour)) {
		return nil, ErrDenied
	}
	w, e := webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "Portico", RPOrigins: []string{c.Origin}, AttestationPreference: protocol.PreferDirectAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{AuthenticatorAttachment: protocol.CrossPlatform, UserVerification: protocol.VerificationRequired}, Filtering: &webauthn.FilteringConfig{ProhibitBackupEligibility: true}})
	if e != nil {
		return nil, ErrDenied
	}
	policy, e := json.Marshal(c)
	if e != nil {
		return nil, ErrDenied
	}
	v := &Verifier{wa: w, origin: c.Origin, roots: map[string]*x509.CertPool{}, validUntil: c.ValidUntil, policyHash: pki.Hash(policy)}
	for _, m := range c.Models {
		if !pki.ValidID(m.AAGUID) || len(m.RootsDER) == 0 || len(m.RootsDER) > 4 || v.roots[m.AAGUID] != nil {
			return nil, ErrDenied
		}
		pool := x509.NewCertPool()
		for _, der := range m.RootsDER {
			c, e := x509.ParseCertificate(der)
			if e != nil || !c.IsCA || c.CheckSignatureFrom(c) != nil {
				return nil, ErrDenied
			}
			pool.AddCert(c)
		}
		v.roots[m.AAGUID] = pool
	}
	return v, nil
}

func validBinding(b Binding) bool {
	return pki.ValidID(b.AdministratorID) && len(b.DeviceCertificateHash) == 64 && len(b.OperationHash) == 64 && b.Revision > 0
}
func (v *Verifier) begin(u User, b Binding, kind string) (Session, error) {
	now := time.Now().UTC()
	if !validBinding(b) || u.ID != b.AdministratorID || !now.Before(v.validUntil) || len(u.Credentials) > 8 {
		return Session{}, ErrDenied
	}
	return Session{Binding: b, PolicyHash: v.policyHash, Kind: kind, CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, nil
}
func (v *Verifier) validSession(s Session, u User, b Binding, kind string) bool {
	now := time.Now().UTC()
	return validBinding(b) && s.Binding == b && s.PolicyHash == v.policyHash && u.ID == b.AdministratorID && s.Kind == kind && !now.Before(s.CreatedAt) && now.Before(s.ExpiresAt) && s.ExpiresAt.Sub(s.CreatedAt) == 2*time.Minute && now.Before(v.validUntil) && s.Data.UserVerification == protocol.VerificationRequired && bytes.Equal(s.Data.UserID, []byte(u.ID))
}

func (v *Verifier) BeginRegistration(u User, b Binding) (*protocol.CredentialCreation, Session, error) {
	s, e := v.begin(u, b, "registration")
	if e != nil {
		return nil, s, e
	}
	opts, data, e := v.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Credentials).CredentialDescriptors()))
	if e != nil {
		return nil, Session{}, ErrDenied
	}
	s.Data = *data
	return opts, s, nil
}
func (v *Verifier) VerifyRegistration(u User, s Session, b Binding, response []byte) (*webauthn.Credential, error) {
	if len(response) == 0 || len(response) > MaxResponse || !v.validSession(s, u, b, "registration") {
		return nil, ErrDenied
	}
	parsed, e := protocol.ParseCredentialCreationResponseBytes(response)
	if e != nil {
		return nil, ErrDenied
	}
	c, e := v.wa.CreateCredential(u, s.Data, parsed)
	if e != nil || !acceptable(c) || v.attestation(c, parsed.Response.AttestationObject) != nil {
		return nil, ErrDenied
	}
	for _, existing := range u.Credentials {
		if bytes.Equal(c.ID, existing.ID) || bytes.Equal(c.PublicKey, existing.PublicKey) {
			return nil, ErrDenied
		}
	}
	return c, nil
}

func acceptable(c *webauthn.Credential) bool {
	return c != nil && len(c.ID) > 0 && len(c.ID) <= 1024 && c.AttestationFormat == "packed" && c.AttestationType == "basic_full" && c.Flags.UserPresent && c.Flags.UserVerified && !c.Flags.BackupEligible && !c.Flags.BackupState && !c.Authenticator.CloneWarning
}
func (v *Verifier) attestation(c *webauthn.Credential, a protocol.AttestationObject) error {
	if a.Format != "packed" || a.AuthData.Unmarshal(a.RawAuthData) != nil || !bytes.Equal(a.AuthData.AttData.AAGUID, c.Authenticator.AAGUID) || !bytes.Equal(a.AuthData.AttData.CredentialID, c.ID) || !bytes.Equal(a.AuthData.AttData.CredentialPublicKey, c.PublicKey) || len(c.Authenticator.AAGUID) != 16 {
		return ErrDenied
	}
	// UUID text is derived from authenticated attested data, never client hints.
	id := fmtAAGUID(c.Authenticator.AAGUID)
	roots := v.roots[id]
	if roots == nil {
		return ErrDenied
	}
	chain, ok := a.AttStatement["x5c"].([]any)
	if !ok || len(chain) == 0 || len(chain) > 4 {
		return ErrDenied
	}
	pool := x509.NewCertPool()
	var leaf *x509.Certificate
	for i, item := range chain {
		der, ok := item.([]byte)
		if !ok || len(der) > pki.MaxDER {
			return ErrDenied
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return ErrDenied
		}
		if i == 0 {
			leaf = cert
		} else {
			pool.AddCert(cert)
		}
	}
	if leaf.IsCA {
		return ErrDenied
	}
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); e != nil {
		return ErrDenied
	}
	return nil
}

func (v *Verifier) BeginApproval(u User, b Binding) (*protocol.CredentialAssertion, Session, error) {
	s, e := v.begin(u, b, "approval")
	if e != nil || len(u.Credentials) == 0 {
		return nil, Session{}, ErrDenied
	}
	opts, data, e := v.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if e != nil {
		return nil, Session{}, ErrDenied
	}
	s.Data = *data
	return opts, s, nil
}
func (v *Verifier) VerifyApproval(u User, s Session, b Binding, response []byte) (*webauthn.Credential, error) {
	if len(response) == 0 || len(response) > MaxResponse || !v.validSession(s, u, b, "approval") {
		return nil, ErrDenied
	}
	// Deep-copy persisted records before the library updates flags and counters.
	encoded, e := json.Marshal(u)
	if e != nil || json.Unmarshal(encoded, &u) != nil {
		return nil, ErrDenied
	}
	parsed, e := protocol.ParseCredentialRequestResponseBytes(response)
	if e != nil {
		return nil, ErrDenied
	}
	c, e := v.wa.ValidateLogin(u, s.Data, parsed)
	if e != nil || !acceptable(c) {
		return nil, ErrDenied
	}
	// Revalidate the original packed attestation against the current local trust
	// policy on every approval, including expiry of its chain and policy snapshot.
	var att protocol.AttestationObject
	if e = decodeAttestation(c.Attestation.Object, &att); e != nil || att.AuthData.Unmarshal(att.RawAuthData) != nil || v.attestation(c, att) != nil {
		return nil, ErrDenied
	}
	hash := sha256.Sum256(c.Attestation.ClientDataJSON)
	if att.VerifyAttestation(hash[:], nil, v.wa.Config.Attestation, v.wa.Config.Signature) != nil {
		return nil, ErrDenied
	}
	return c, nil
}
