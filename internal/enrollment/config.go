package enrollment

import (
	"context"
	"path"
	"strings"
	"time"

	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

// FileConfig is approved public enrollment configuration. It has no inline key,
// invitation bearer secret, administrator profile or trust-discovery mechanism.
type FileConfig struct {
	Version                int                        `json:"version"`
	DeploymentID           string                     `json:"deployment_id"`
	Profile                pki.Profile                `json:"profile"`
	Issuer                 identityfile.TrustFiles    `json:"issuer"`
	PrincipalID            string                     `json:"principal_id"`
	InvitationID           string                     `json:"invitation_id"`
	NotAfter               string                     `json:"not_after"`
	StateFile              string                     `json:"state_file"`
	Redemption             identityfile.EndpointFiles `json:"redemption"`
	Activation             identityfile.EndpointFiles `json:"activation"`
	OperationTimeoutMillis int                        `json:"operation_timeout_ms"`
}

type Configuration struct {
	client                Config
	invitation, stateFile string
}

func LoadConfig(file string) (*Configuration, error) { return loadConfig(file, localfile.Read) }

func loadConfig(file string, read identityfile.Reader) (*Configuration, error) {
	data, err := read(file, wire.MaxBody, false)
	var input FileConfig
	if err != nil || wire.Decode(data, &input) != nil || input.Version != 1 || (input.Profile != pki.Device && input.Profile != pki.Connector) || input.OperationTimeoutMillis < 1 || input.OperationTimeoutMillis > 5000 || !path.IsAbs(input.StateFile) || path.Clean(input.StateFile) != input.StateFile || input.StateFile == "/" || strings.ContainsRune(input.StateFile, 0) || len(input.StateFile)+len(".certificate") > 4096 {
		return nil, ErrRejected
	}
	notAfter, err := time.Parse(time.RFC3339, input.NotAfter)
	if err != nil || notAfter.UTC().Format(time.RFC3339) != input.NotAfter {
		return nil, ErrRejected
	}
	trust, err := read.Trust(input.DeploymentID, input.Issuer, input.Profile)
	if err != nil {
		return nil, ErrRejected
	}
	redemptionRoot, err := read.Certificate(input.Redemption.RootCertificateFile)
	if err != nil {
		return nil, ErrRejected
	}
	activationRoot, err := read.Certificate(input.Activation.RootCertificateFile)
	if err != nil {
		return nil, ErrRejected
	}
	c := Config{
		Redemption: Endpoint{URL: input.Redemption.URL, ServerRootDER: redemptionRoot, ServerSPKI: input.Redemption.SPKI},
		Activation: Endpoint{URL: input.Activation.URL, ServerRootDER: activationRoot, ServerSPKI: input.Activation.SPKI},
		Trust:      trust, PrincipalID: input.PrincipalID, NotAfter: notAfter, Timeout: time.Duration(input.OperationTimeoutMillis) * time.Millisecond, MaxRequests: 1,
	}
	if _, err := bindingFor(c, input.InvitationID); err != nil {
		return nil, ErrRejected
	}
	return &Configuration{client: c, invitation: input.InvitationID, stateFile: input.StateFile}, nil
}

// Prepare is deliberately separate from redemption. Missing state in Redeem
// never causes automatic key generation after an uncertain earlier request.
func (c *Configuration) Prepare(passphrase []byte) error {
	if c == nil {
		return ErrRejected
	}
	_, err := CreateAttempt(c.stateFile, c.client, c.invitation, passphrase)
	return err
}

func (c *Configuration) Redeem(ctx context.Context, passphrase []byte, secret string) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	a, err := OpenAttempt(c.stateFile, c.client, c.invitation, passphrase)
	if err != nil {
		return ErrRejected
	}
	client, err := New(c.client)
	if err != nil {
		return ErrRejected
	}
	defer client.Close()
	return a.Redeem(ctx, client, secret)
}

func (c *Configuration) Activate(ctx context.Context, passphrase []byte) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	a, err := OpenAttempt(c.stateFile, c.client, c.invitation, passphrase)
	if err != nil {
		return ErrRejected
	}
	client, err := New(c.client)
	if err != nil {
		return ErrRejected
	}
	defer client.Close()
	return a.Activate(ctx, client)
}
