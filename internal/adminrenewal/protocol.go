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

// These operations terminate in native code. The renderer cannot supply a CSR,
// key, certificate, network destination or replacement-file path.
const StatusPath = "/api/v1/admin/native-renewal/status"
const StartPath = "/api/v1/admin/native-renewal/start"
const ApprovePath = "/api/v1/admin/native-renewal/approve"
const ResumePath = "/api/v1/admin/native-renewal/resume"
const CancelPath = "/api/v1/admin/native-renewal/cancel"

type StartRequest struct {
	Version        int
	NotAfter       time.Time
	PolicyRevision int64
}

type NativeRequest struct{ Version int }

type Prepared struct {
	Version                int
	RenewalID              string
	CSRHash                string
	CurrentCertificateHash string
	NotAfter               time.Time
	ExpiresAt              time.Time
	PolicyRevision         int64
	Challenge              json.RawMessage
}

type Status struct {
	Version                int
	State                  string
	RenewalID              string
	CurrentCertificateHash string
	CurrentNotAfter        time.Time
	RequestedNotAfter      time.Time
	Prepared               *Prepared `json:",omitempty"`
}

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
