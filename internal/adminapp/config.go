// Package adminapp connects protected administrator configuration and encrypted
// device keys to the native window. It is separate from ordinary client roles.
package adminapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/adminkey"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
)

var ErrRejected = errors.New("administrator application rejected")

// There is no plaintext key, executable, browser argument, environment, clock
// estimate or alternate network destination in this format.
type FileConfig struct {
	Version                 int                        `json:"version"`
	DeploymentID            string                     `json:"deployment_id"`
	PrincipalID             string                     `json:"principal_id"`
	Administrators          identityfile.TrustFiles    `json:"administrators"`
	IdentityCertificateFile string                     `json:"identity_certificate_file"`
	EncryptedKeyFile        string                     `json:"encrypted_key_file"`
	Server                  identityfile.EndpointFiles `json:"server"`
	BootstrapAddress        string                     `json:"bootstrap_address,omitempty"`
	Socket                  string                     `json:"socket,omitempty"`
	StateDirectory          string                     `json:"state_directory"`
	OperationTimeoutMillis  int                        `json:"operation_timeout_ms"`
	SessionLifetimeSeconds  int                        `json:"session_lifetime_seconds"`
	Renewal                 *RenewalFiles              `json:"renewal,omitempty"`
}

type RenewalFiles struct {
	Server           identityfile.EndpointFiles `json:"server"`
	BootstrapAddress string                     `json:"bootstrap_address,omitempty"`
	Socket           string                     `json:"socket,omitempty"`
}

type Configuration struct {
	bridge                    adminbridge.Config
	leaf                      []byte
	keyPath, principal, state string
	renewal                   *adminbridge.Config
	binding                   string
}

func pathValid(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsRune(path, 0)
}

func Load(path string) (*Configuration, error) { return load(path, localfile.Read) }

func load(path string, read identityfile.Reader) (*Configuration, error) {
	data, err := read(path, wire.MaxBody, false)
	var f FileConfig
	if err != nil || wire.Decode(data, &f) != nil || (f.Version != 1 && f.Version != 2) || (f.Version == 2) != (f.Renewal != nil) || !pki.ValidID(f.DeploymentID) || !pki.ValidID(f.PrincipalID) || !pathValid(f.EncryptedKeyFile) || !pathValid(f.StateDirectory) || f.OperationTimeoutMillis < 1 || f.OperationTimeoutMillis > 5000 || f.SessionLifetimeSeconds < 1 || f.SessionLifetimeSeconds > 600 {
		return nil, ErrRejected
	}
	bridge, err := readEndpoint(read, f.Server, f.BootstrapAddress, f.Socket)
	if err != nil {
		return nil, ErrRejected
	}
	trust, err := read.Trust(f.DeploymentID, f.Administrators, pki.Administrator)
	if err != nil {
		return nil, ErrRejected
	}
	leaf, err := read.Certificate(f.IdentityCertificateFile)
	if err != nil {
		return nil, ErrRejected
	}
	credential, err := trust.VerifyPeer(leaf, time.Now().UTC())
	if f.Version == 2 {
		credential, err = historicalCredential(trust, f.PrincipalID, leaf)
	}
	if err != nil || credential.PrincipalID != f.PrincipalID {
		return nil, ErrRejected
	}
	bridge.AdministratorTrust, bridge.Timeout, bridge.Lifetime = trust, time.Duration(f.OperationTimeoutMillis)*time.Millisecond, time.Duration(f.SessionLifetimeSeconds)*time.Second
	c := &Configuration{bridge: bridge, leaf: leaf, keyPath: f.EncryptedKeyFile, principal: f.PrincipalID, state: f.StateDirectory}
	if f.Renewal != nil {
		activation, err := readEndpoint(read, f.Renewal.Server, f.Renewal.BootstrapAddress, f.Renewal.Socket)
		if err != nil || (f.Renewal.BootstrapAddress == f.BootstrapAddress && f.Renewal.Socket == f.Socket) {
			return nil, ErrRejected
		}
		activation.AdministratorTrust, activation.Timeout, activation.Lifetime = trust, bridge.Timeout, bridge.Lifetime
		c.renewal = &activation
		// Bind the public journal to independently loaded configuration and trust,
		// including routes and actual certificate contents, not filenames alone.
		binding, err := json.Marshal(struct {
			Config                                            FileConfig
			Initial, Root, Issuer, ServerRoot, ActivationRoot string
		}{f, pki.Hash(leaf), trust.RootFingerprint(), trust.IssuerFingerprint(), pki.Hash(bridge.ServerRootDER), pki.Hash(activation.ServerRootDER)})
		if err != nil {
			return nil, ErrRejected
		}
		c.binding = pki.Hash(binding)
	}
	return c, nil
}

func readEndpoint(read identityfile.Reader, files identityfile.EndpointFiles, address, socket string) (adminbridge.Config, error) {
	if !adminbridge.Origin(files.URL) || (address == "") == (socket == "") {
		return adminbridge.Config{}, ErrRejected
	}
	if address != "" {
		a, err := netip.ParseAddrPort(address)
		if err != nil || !a.Addr().IsLoopback() || a.Addr().Is4In6() || a.Addr().Zone() != "" || a.Port() == 0 || a.String() != address {
			return adminbridge.Config{}, ErrRejected
		}
	} else if !pathValid(socket) {
		return adminbridge.Config{}, ErrRejected
	}
	spki, err := hex.DecodeString(files.SPKI)
	if err != nil || len(spki) != 32 || hex.EncodeToString(spki) != files.SPKI {
		return adminbridge.Config{}, ErrRejected
	}
	rootDER, err := read.Certificate(files.RootCertificateFile)
	if err != nil {
		return adminbridge.Config{}, ErrRejected
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid || root.CheckSignatureFrom(root) != nil {
		return adminbridge.Config{}, ErrRejected
	}
	return adminbridge.Config{Origin: files.URL, ServerSPKI: files.SPKI, ServerRootDER: rootDER, BootstrapAddress: address, Socket: socket}, nil
}

type deviceKey interface {
	Identity([]byte) (tls.Certificate, error)
	Close()
}
type openKey func(string, *pki.Trust, string, []byte) (deviceKey, error)
type prepareWindow func(string) (adminbridge.Launch, func(), error)
type runWindow func(context.Context, *adminbridge.Client, adminbridge.Launch) error

// Run owns the unlocked signer until the child and bridge have joined. The
// passphrase is consumed and cleared, including on failure. Cancellation after a synchronous KDF still
// revokes the returned handle before any browser starts.
func (c *Configuration) Run(ctx context.Context, passphrase []byte) error {
	return c.run(ctx, passphrase, func(path string, trust *pki.Trust, principal string, pass []byte) (deviceKey, error) {
		return adminkey.Open(path, trust, principal, pass)
	}, prepareInstalled, adminbridge.Run)
}

func (c *Configuration) run(ctx context.Context, passphrase []byte, open openKey, prepare prepareWindow, run runWindow) error {
	defer clear(passphrase)
	if c == nil || ctx == nil || ctx.Err() != nil || len(passphrase) < 16 || len(passphrase) > 1024 {
		return ErrRejected
	}
	spec, release, err := prepare(c.state)
	if err != nil {
		return ErrRejected
	}
	defer release()
	if ctx.Err() != nil {
		return ErrRejected
	}
	key, err := open(c.keyPath, c.bridge.AdministratorTrust, c.principal, passphrase)
	clear(passphrase)
	if key != nil {
		defer key.Close()
	}
	if err != nil || key == nil || ctx.Err() != nil {
		return ErrRejected
	}
	config := c.bridge
	leaf := c.leaf
	if c.renewal != nil {
		renewable, ok := key.(renewalKey)
		if !ok {
			return ErrRejected
		}
		storage, err := openCredentialDisk(c.state)
		if err != nil {
			return ErrRejected
		}
		defer storage.Close()
		renewal, err := newNativeRenewal(c, renewable, storage)
		if err != nil {
			return ErrRejected
		}
		// A durably retained candidate can be reconciled after a crash even if
		// the predecessor has since expired or was retired by remote activation.
		if p := renewal.journal.record.Pending; p != nil && p.Phase == "issued" {
			if renewal.activate(ctx) != nil {
				return ErrRejected
			}
			renewal.completed = false // This new window uses the selected new leaf.
		}
		leaf = renewal.journal.record.Certificate
		config.RenewalHandler = renewal.Handle
	}
	identity, err := key.Identity(leaf)
	if err != nil || ctx.Err() != nil {
		return ErrRejected
	}
	config.Identity = identity
	bridge, err := adminbridge.New(ctx, config)
	if err != nil {
		return ErrRejected
	}
	defer bridge.Close()
	if run(ctx, bridge, spec) != nil || ctx.Err() != nil {
		return ErrRejected
	}
	return nil
}
