// Package client implements device resource discovery and authenticated access.
package client

import (
	"context"
	"errors"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/wire"
	"portico.local/portico/internal/workload"
)

var ErrConfiguration = errors.New("client configuration rejected")
var ErrConnection = errors.New("client resource connection rejected")

type TrustFiles = identityfile.TrustFiles
type EndpointFiles = identityfile.EndpointFiles

// No destination, grant, username, inline key or clock override is accepted.
type FileConfig struct {
	Version                 int           `json:"version"`
	DeploymentID            string        `json:"deployment_id"`
	Devices                 TrustFiles    `json:"devices"`
	Connectors              TrustFiles    `json:"connectors"`
	IdentityCertificateFile string        `json:"identity_certificate_file"`
	IdentityKeyFile         string        `json:"identity_key_file"`
	Control                 EndpointFiles `json:"control"`
	Carrier                 EndpointFiles `json:"carrier"`
	OperationTimeoutMillis  int           `json:"operation_timeout_ms"`
	IdleTimeoutSeconds      int           `json:"idle_timeout_seconds"`
}

type Configuration struct {
	workload workload.ClientConfig
	control  control.ClientConfig
	carrier  carrier.ClientConfig
}

func LoadConfig(path string) (*Configuration, error) { return loadConfig(path, localfile.Read) }

func loadConfig(path string, read identityfile.Reader) (*Configuration, error) {
	data, err := read(path, wire.MaxBody, false)
	var file FileConfig
	if err != nil || wire.Decode(data, &file) != nil || file.Version != 1 || !pki.ValidID(file.DeploymentID) || file.OperationTimeoutMillis < 1 || file.OperationTimeoutMillis > 5000 || file.IdleTimeoutSeconds < 1 || file.IdleTimeoutSeconds > 900 || !identityfile.LoopbackEndpoint(file.Control.URL) || !identityfile.LoopbackEndpoint(file.Carrier.URL) {
		return nil, ErrConfiguration
	}
	devices, err := read.Trust(file.DeploymentID, file.Devices, pki.Device)
	if err != nil {
		return nil, ErrConfiguration
	}
	connectors, err := read.Trust(file.DeploymentID, file.Connectors, pki.Connector)
	if err != nil {
		return nil, ErrConfiguration
	}
	identity, err := read.Identity(devices, file.IdentityCertificateFile, file.IdentityKeyFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	controllerRoot, err := read.Certificate(file.Control.RootCertificateFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	carrierRoot, err := read.Certificate(file.Carrier.RootCertificateFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	operation := time.Duration(file.OperationTimeoutMillis) * time.Millisecond
	return &Configuration{
		workload: workload.ClientConfig{Devices: devices, Connectors: connectors, Identity: identity, MaxConnections: 1, OperationTimeout: operation, IdleTimeout: time.Duration(file.IdleTimeoutSeconds) * time.Second, ClockHealth: clockhealth.Uncertainty},
		control:  control.ClientConfig{Endpoint: file.Control.URL, ServerRootDER: controllerRoot, ServerSPKI: file.Control.SPKI, Identity: identity, Profile: pki.Device, Timeout: operation, MaxConnections: 2},
		carrier:  carrier.ClientConfig{Endpoint: file.Carrier.URL, ServerRootDER: carrierRoot, ServerSPKI: file.Carrier.SPKI, Identity: identity, MaxStreams: 1, OpenTimeout: operation, MaxLifetime: time.Hour},
	}, nil
}

func (c *Configuration) openControl(ctx context.Context) (*control.Client, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrConfiguration
	}
	if _, err := clockhealth.Uncertainty(); err != nil {
		return nil, err
	}
	controller, err := control.NewClient(c.control)
	if err != nil {
		return nil, ErrConfiguration
	}
	return controller, nil
}

func (c *Configuration) Catalog(ctx context.Context) ([]control.ResourceAccess, error) {
	controller, err := c.openControl(ctx)
	if err != nil {
		return nil, err
	}
	defer controller.Close()
	resources, err := controller.Catalog(ctx)
	if err != nil {
		return nil, ErrConnection
	}
	return resources, nil
}

type connection struct {
	stream   *workload.Conn
	workload *workload.Client
	carrier  *carrier.Client
	control  *control.Client
}

func (c *connection) close() {
	if c.stream != nil {
		_ = c.stream.Close()
	}
	if c.workload != nil {
		c.workload.Close()
	}
	if c.carrier != nil {
		_ = c.carrier.Close()
	}
	if c.control != nil {
		c.control.Close()
	}
}

// Selection is by immutable ID and explicit revision. A fresh private catalog
// locates the tuple; the workload independently authenticates/authorizes it.
// There is no cached grant, destination override or automatic revision upgrade.
func (c *Configuration) open(ctx context.Context, id string, revision int64) (_ *connection, err error) {
	if !pki.ValidID(id) || revision < 1 {
		return nil, ErrConnection
	}
	controller, err := c.openControl(ctx)
	if err != nil {
		return nil, err
	}
	v := &connection{control: controller}
	defer func() {
		if err != nil {
			v.close()
		}
	}()
	resources, err := controller.Catalog(ctx)
	if err != nil {
		return nil, ErrConnection
	}
	var selected *control.ResourceAccess
	for i := range resources {
		if resources[i].ID == id && resources[i].Revision == revision {
			selected = &resources[i]
			break
		}
	}
	if selected == nil {
		return nil, ErrConnection
	}
	config := c.workload
	config.Control = controller
	v.workload, err = workload.NewClient(ctx, config)
	if err != nil {
		return nil, ErrConnection
	}
	v.carrier, err = carrier.NewClient(c.carrier)
	if err != nil {
		return nil, ErrConnection
	}
	raw, err := v.carrier.Dial(ctx, selected.ConnectorID)
	if err != nil {
		return nil, ErrConnection
	}
	v.stream, err = v.workload.Open(ctx, raw, *selected)
	if err != nil {
		return nil, ErrConnection
	}
	return v, nil
}
