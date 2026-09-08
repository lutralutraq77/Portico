package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/netip"
	"net/url"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
	"portico.local/portico/internal/workload"
)

type TrustFiles struct {
	IssuerID              string `json:"issuer_id"`
	RootCertificateFile   string `json:"root_certificate_file"`
	IssuerCertificateFile string `json:"issuer_certificate_file"`
}
type EndpointFiles struct {
	URL                 string `json:"url"`
	RootCertificateFile string `json:"root_certificate_file"`
	SPKI                string `json:"spki_sha256"`
}
type DestinationFile struct {
	ResourceID string `json:"resource_id"`
	Revision   int64  `json:"revision"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
}

// FileConfig contains public identifiers, explicit destinations and local file
// paths. Private keys and a claimed clock-health bound cannot appear inline.
type FileConfig struct {
	Version                 int               `json:"version"`
	DeploymentID            string            `json:"deployment_id"`
	CertificateID           string            `json:"certificate_id"`
	Devices                 TrustFiles        `json:"devices"`
	Connectors              TrustFiles        `json:"connectors"`
	IdentityCertificateFile string            `json:"identity_certificate_file"`
	IdentityKeyFile         string            `json:"identity_key_file"`
	Control                 EndpointFiles     `json:"control"`
	Carrier                 EndpointFiles     `json:"carrier"`
	Destinations            []DestinationFile `json:"destinations"`
	ProtectedNetworks       []string          `json:"protected_networks"`
	Workers                 int               `json:"workers"`
	MaxDeviceSessions       int               `json:"max_device_sessions"`
	OperationTimeoutMillis  int               `json:"operation_timeout_ms"`
	IdleTimeoutSeconds      int               `json:"idle_timeout_seconds"`
}

// Configuration has no public mutable authority fields. LoadConfig performs
// bounded file/trust checks; Run also applies the workload runtime's complete
// destination/limit checks and the native clock-health gate before any binding.
type Configuration struct {
	server  workload.ServerConfig
	control control.ClientConfig
	carrier carrier.ClientConfig
	options Options
}

func LoadConfig(path string) (*Configuration, error) { return loadConfig(path, localfile.Read) }

func loadConfig(path string, read func(string, int64, bool) ([]byte, error)) (*Configuration, error) {
	data, err := read(path, wire.MaxBody, false)
	var file FileConfig
	if err != nil || wire.Decode(data, &file) != nil || file.Version != 1 || !pki.ValidID(file.DeploymentID) || !pki.ValidID(file.CertificateID) || file.Workers < 1 || file.Workers > 64 || file.MaxDeviceSessions < 1 || file.MaxDeviceSessions > file.Workers || file.OperationTimeoutMillis < 1 || file.OperationTimeoutMillis > 5000 || file.IdleTimeoutSeconds < 1 || file.IdleTimeoutSeconds > 900 || len(file.Destinations) < 1 || len(file.Destinations) > 64 || len(file.ProtectedNetworks) < 1 || len(file.ProtectedNetworks) > 256 || !loopbackEndpoint(file.Control.URL) || !loopbackEndpoint(file.Carrier.URL) {
		return nil, ErrConfiguration
	}
	certificate := func(path string) ([]byte, error) {
		data, err := read(path, 2*pki.MaxDER, false)
		block, rest := pem.Decode(data)
		if err != nil || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > pki.MaxDER || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrConfiguration
		}
		return block.Bytes, nil
	}
	trust := func(files TrustFiles, profile pki.Profile) (*pki.Trust, error) {
		root, err := certificate(files.RootCertificateFile)
		if err != nil {
			return nil, err
		}
		issuer, err := certificate(files.IssuerCertificateFile)
		if err != nil {
			return nil, err
		}
		return pki.NewTrust(pki.Config{DeploymentID: file.DeploymentID, IssuerID: files.IssuerID, Profile: profile, RootDER: root, IssuerDER: issuer})
	}
	devices, err := trust(file.Devices, pki.Device)
	if err != nil {
		return nil, ErrConfiguration
	}
	connectors, err := trust(file.Connectors, pki.Connector)
	if err != nil {
		return nil, ErrConfiguration
	}
	leaf, err := certificate(file.IdentityCertificateFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	key, err := read(file.IdentityKeyFile, pki.MaxDER, true)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer clear(key)
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrConfiguration
	}
	defer clear(block.Bytes)
	identity, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), key)
	if err != nil {
		return nil, ErrConfiguration
	}
	identity, err = connectors.TLSIdentity(identity)
	if err != nil {
		return nil, ErrConfiguration
	}
	controllerRoot, err := certificate(file.Control.RootCertificateFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	carrierRoot, err := certificate(file.Carrier.RootCertificateFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	var approved []workload.Destination
	for _, d := range file.Destinations {
		approved = append(approved, workload.Destination{ResourceID: d.ResourceID, Revision: d.Revision, Address: d.Address, Port: d.Port, Protocol: d.Protocol})
	}
	var protected []netip.Prefix
	for _, text := range file.ProtectedNetworks {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.String() != text || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, ErrConfiguration
		}
		protected = append(protected, prefix)
	}
	operation := time.Duration(file.OperationTimeoutMillis) * time.Millisecond
	return &Configuration{
		server:  workload.ServerConfig{Devices: devices, Connectors: connectors, Identity: identity, CertificateID: file.CertificateID, Approved: approved, ProtectedNetworks: protected, MaxSessions: file.Workers, MaxDeviceSessions: file.MaxDeviceSessions, OperationTimeout: operation, IdleTimeout: time.Duration(file.IdleTimeoutSeconds) * time.Second, ClockHealth: clockhealth.Uncertainty},
		control: control.ClientConfig{Endpoint: file.Control.URL, ServerRootDER: controllerRoot, ServerSPKI: file.Control.SPKI, Identity: identity, Profile: pki.Connector, Timeout: operation, MaxConnections: min(file.Workers+1, 32)},
		carrier: carrier.ClientConfig{Endpoint: file.Carrier.URL, ServerRootDER: carrierRoot, ServerSPKI: file.Carrier.SPKI, Identity: identity, MaxStreams: file.Workers, OpenTimeout: operation, MaxLifetime: time.Hour},
		options: Options{Workers: file.Workers, RetryMin: 500 * time.Millisecond, RetryMax: 5 * time.Second},
	}, nil
}

// The Phase 5 development command talks only to loopback control/carrier
// services. Broader deployment endpoints require the independent network gate.
func loopbackEndpoint(text string) bool {
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "https" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(u.Hostname())
	return err == nil && address.IsLoopback() && !address.Is4In6() && address.Zone() == "" && address.String() == u.Hostname()
}

// Run creates a new runtime with live native clock health. It installs no
// service, changes no clock and has no fixture-health/configuration override.
func (c *Configuration) Run(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrConfiguration
	}
	if _, err := clockhealth.Uncertainty(); err != nil {
		return err
	}
	controller, err := control.NewClient(c.control)
	if err != nil {
		return ErrConfiguration
	}
	defer controller.Close()
	config := c.server
	config.Control = controller
	server, err := workload.NewServer(ctx, config)
	if err != nil {
		return err
	}
	client, err := carrier.NewClient(c.carrier)
	if err != nil {
		server.Close()
		return ErrConfiguration
	}
	return Run(ctx, client, server, c.options)
}
