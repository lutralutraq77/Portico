// Package adminrenewal defines separate approval and activation wire formats.
// It carries public record identifiers and certificate hashes, never a signer.
package adminrenewal

import (
	"encoding/json"
	"time"
)

const Version = 1
const MaxActivationBody = 1024
const ActivatePath = "/api/v1/admin/renewal/activate"
const PreparePath = "/api/v1/admin/renewal/challenge"
const ConfirmPath = "/api/v1/admin/renewal/confirm"
const CertificatePath = "/api/v1/admin/renewal/certificate"

type PrepareRequest struct {
	Version        int
	RenewalID      string
	CSR            []byte
	NotAfter       time.Time
	PolicyRevision int64
}

type ConfirmRequest struct {
	Version     int
	ChallengeID string
	Response    json.RawMessage
}

type CertificateRequest struct {
	Version   int
	RenewalID string
}

type Certificate struct {
	Version        int
	RenewalID      string
	CertificateDER []byte
}

type ActivateRequest struct {
	Version   int
	RenewalID string
}

type Activated struct {
	Version           int
	RenewalID         string
	CertificateSHA256 string
}
