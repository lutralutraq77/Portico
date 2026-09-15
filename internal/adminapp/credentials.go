package adminapp

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"portico.local/portico/internal/adminrenewal"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

// Native orchestration keeps storage separate from network operations so that
// no request can proceed before its prerequisite state is durably committed.
type credentialStorage interface {
	Read() ([]byte, error)
	Commit(previous, next []byte) error
	Close()
}

type credentialRecord struct {
	Version     int
	Purpose     string
	Binding     string
	Certificate []byte
	Pending     *pendingRenewal
}

type pendingRenewal struct {
	Phase       string
	CreatedAt   time.Time
	Request     adminrenewal.PrepareRequest
	Prepared    json.RawMessage `json:",omitempty"`
	Certificate []byte
}

type credentialJournal struct {
	storage credentialStorage
	config  *Configuration
	data    []byte
	record  credentialRecord
	failed  bool
}

type renewalChallenge struct {
	ID       string
	Approval *protocol.CredentialAssertion
}

func historicalCredential(trust *pki.Trust, principal string, der []byte) (pki.Credential, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil || leaf.NotBefore.After(time.Now()) {
		return pki.Credential{}, ErrRejected
	}
	// A retained predecessor may have expired. Verify its signed scope at its
	// validity start; actual transport still requires a currently valid leaf.
	return trust.Verify(der, principal, leaf.NotBefore)
}

func openCredentialJournal(c *Configuration, storage credentialStorage) (*credentialJournal, error) {
	if c == nil || c.renewal == nil || len(c.binding) != 64 || storage == nil {
		return nil, ErrRejected
	}
	data, err := storage.Read()
	if err != nil {
		return nil, ErrRejected
	}
	j := &credentialJournal{storage: storage, config: c, data: bytes.Clone(data)}
	if data == nil {
		r := credentialRecord{Version: 1, Purpose: "portico-native-administrator-credentials", Binding: c.binding, Certificate: bytes.Clone(c.leaf)}
		if j.commit(r) != nil {
			return nil, ErrRejected
		}
	} else if wire.Decode(data, &j.record) != nil || j.validate(j.record) != nil {
		return nil, ErrRejected
	}
	return j, nil
}

func (j *credentialJournal) validate(r credentialRecord) error {
	c := j.config
	if r.Version != 1 || r.Purpose != "portico-native-administrator-credentials" || r.Binding != c.binding {
		return ErrRejected
	}
	base, err := historicalCredential(c.bridge.AdministratorTrust, c.principal, c.leaf)
	if err != nil {
		return ErrRejected
	}
	current, err := historicalCredential(c.bridge.AdministratorTrust, c.principal, r.Certificate)
	if err != nil || current.SPKISHA256 != base.SPKISHA256 || current.NotAfter.Before(base.NotAfter) {
		return ErrRejected
	}
	if r.Pending == nil {
		return nil
	}
	p := r.Pending
	request := p.Request
	csr, err := pki.ParseCSR(request.CSR)
	if err != nil || request.Version != 1 || !pki.ValidID(request.RenewalID) || request.PolicyRevision < 1 || pki.Hash(csr.RawSubjectPublicKeyInfo) != current.SPKISHA256 || p.CreatedAt.IsZero() || p.CreatedAt.After(time.Now()) || !request.NotAfter.Equal(request.NotAfter.Truncate(time.Second)) || !request.NotAfter.After(current.NotAfter) || request.NotAfter.After(c.bridge.AdministratorTrust.NotAfter()) || request.NotAfter.After(p.CreatedAt.Truncate(time.Second).Add(24*time.Hour)) {
		return ErrRejected
	}
	if p.Phase == "preparing" {
		if len(p.Prepared) != 0 || len(p.Certificate) != 0 {
			return ErrRejected
		}
		return nil
	}
	if p.Phase != "prepared" && p.Phase != "confirming" && p.Phase != "issued" {
		return ErrRejected
	}
	if _, _, err := j.prepared(r.Certificate, p); err != nil {
		return ErrRejected
	}
	if p.Phase != "issued" {
		if len(p.Certificate) != 0 {
			return ErrRejected
		}
		return nil
	}
	candidate, err := historicalCredential(c.bridge.AdministratorTrust, c.principal, p.Certificate)
	if err != nil || candidate.SPKISHA256 != current.SPKISHA256 || !candidate.NotAfter.Equal(request.NotAfter) || candidate.LeafSHA256 == current.LeafSHA256 {
		return ErrRejected
	}
	return nil
}

func (j *credentialJournal) prepared(current []byte, p *pendingRenewal) (adminrenewal.Prepared, renewalChallenge, error) {
	var prepared adminrenewal.Prepared
	var challenge renewalChallenge
	if wire.Decode(p.Prepared, &prepared) != nil || prepared.Version != 1 || prepared.RenewalID != p.Request.RenewalID || prepared.CSRHash != pki.Hash(p.Request.CSR) || prepared.CurrentCertificateHash != pki.Hash(current) || !prepared.NotAfter.Equal(p.Request.NotAfter) || !prepared.ExpiresAt.After(p.CreatedAt) || prepared.ExpiresAt.After(time.Now().Add(3*time.Minute)) || prepared.PolicyRevision != p.Request.PolicyRevision || wire.Decode(prepared.Challenge, &challenge) != nil || !pki.ValidID(challenge.ID) || challenge.Approval == nil {
		return prepared, challenge, ErrRejected
	}
	u, err := url.Parse(j.config.bridge.Origin)
	options := challenge.Approval.Response
	if err != nil || options.RelyingPartyID != u.Hostname() || options.UserVerification != protocol.VerificationRequired || len(options.Challenge) < 16 || len(options.Challenge) > 1024 || len(options.AllowedCredentials) < 1 || len(options.AllowedCredentials) > 64 {
		return prepared, challenge, ErrRejected
	}
	return prepared, challenge, nil
}

func (j *credentialJournal) commit(r credentialRecord) error {
	if j.failed || j.validate(r) != nil {
		return ErrRejected
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > maxCredentialState || j.storage.Commit(j.data, data) != nil {
		j.failed = true
		return ErrRejected
	}
	// Decode our serialized bytes to avoid retaining a caller-owned byte slice.
	var stored credentialRecord
	if wire.Decode(data, &stored) != nil {
		j.failed = true
		return ErrRejected
	}
	j.data, j.record = data, stored
	return nil
}

func (j *credentialJournal) next() credentialRecord {
	var r credentialRecord
	if wire.Decode(j.data, &r) != nil {
		j.failed = true
	}
	return r
}
