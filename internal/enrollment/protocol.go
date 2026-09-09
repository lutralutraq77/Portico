// Package enrollment implements the restricted ordinary-enrollment client.
// Invitation authority stays at the controller; no issuer credential crosses
// this interface and no caller can request an administrator profile.
package enrollment

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"portico.local/portico/internal/pki"
)

const Version = 1
const MaxBody = 16 * 1024
const RedeemPath = "/api/v1/enrollment/redeem"
const ActivatePath = "/api/v1/enrollment/activate"

var ErrRejected = errors.New("enrollment request rejected")

type RedeemRequest struct {
	Version                         int
	InvitationID, Secret, AttemptID string
	CSR                             []byte
}
type CertificateResponse struct {
	Version                 int
	InvitationID, AttemptID string
	CertificateDER          []byte
}
type ActivateRequest struct {
	Version      int
	InvitationID string
}
type Activated struct {
	Version      int
	InvitationID string
}

func (r RedeemRequest) Valid() bool {
	if r.Version != Version || !pki.ValidID(r.InvitationID) || !pki.ValidID(r.AttemptID) || len(r.Secret) != 43 || len(r.CSR) == 0 || len(r.CSR) > pki.MaxCSR {
		return false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(r.Secret)
	defer clear(secret)
	return err == nil && len(secret) == 32
}

// NewRequest signs an empty proof-only CSR using a locally owned signer. The
// caller must durably retain its key and attempt ID before sending the request.
// Re-signing with the same key/attempt is safe; creating another attempt after
// an uncertain response is not a recovery procedure.
func NewRequest(invitationID, secret, attemptID string, key crypto.Signer) (RedeemRequest, error) {
	if key == nil {
		return RedeemRequest{}, ErrRejected
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	r := RedeemRequest{Version: Version, InvitationID: invitationID, Secret: secret, AttemptID: attemptID, CSR: csr}
	if err != nil || !r.Valid() {
		return RedeemRequest{}, ErrRejected
	}
	if _, err := pki.ParseCSR(csr); err != nil {
		return RedeemRequest{}, ErrRejected
	}
	return r, nil
}
