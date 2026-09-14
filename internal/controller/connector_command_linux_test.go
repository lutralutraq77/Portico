//go:build linux

package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/connector"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

func guestConnectorConfiguration(t *testing.T, v *workloadFixture, workers int) (string, connector.FileConfig, *control.Client) {
	t.Helper()
	requireWorkloadGuest(t)
	p := v.carrier.policy
	client, controlConfig := serveControlClient(t, p, pki.Connector)
	dir, err := os.MkdirTemp("/", "portico-command-")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	write := func(name, kind string, der []byte) string {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600))
		return path
	}
	trust := func(name string, c pki.Config) connector.TrustFiles {
		return connector.TrustFiles{IssuerID: c.IssuerID, RootCertificateFile: write(name+"-root.pem", "CERTIFICATE", c.RootDER), IssuerCertificateFile: write(name+"-issuer.pem", "CERTIFICATE", c.IssuerDER)}
	}
	key, err := x509.MarshalPKCS8PrivateKey(p.connectorIdentity.PrivateKey)
	must(t, err)
	defer clear(key)
	var certificateID string
	must(t, p.device.f.s.db.QueryRow("SELECT id FROM certificates WHERE leaf_sha256=?", pki.Hash(p.connectorLeaf)).Scan(&certificateID))
	r := v.resource
	file := connector.FileConfig{
		Version: 1, DeploymentID: p.device.config.DeploymentID, CertificateID: certificateID,
		Devices: trust("device", p.device.config), Connectors: trust("connector", p.connector.config),
		IdentityCertificateFile: write("identity.pem", "CERTIFICATE", p.connectorLeaf), IdentityKeyFile: write("key.pem", "PRIVATE KEY", key),
		Control:           connector.EndpointFiles{URL: controlConfig.Endpoint, RootCertificateFile: write("control-root.pem", "CERTIFICATE", controlConfig.ServerRootDER), SPKI: controlConfig.ServerSPKI},
		Carrier:           connector.EndpointFiles{URL: v.carrier.connectorConfig.Endpoint, RootCertificateFile: write("carrier-root.pem", "CERTIFICATE", v.carrier.connectorConfig.ServerRootDER), SPKI: v.carrier.connectorConfig.ServerSPKI},
		Destinations:      []connector.DestinationFile{{ResourceID: r.ID, Revision: r.Revision, Address: r.Address, Port: r.Port, Protocol: r.Protocol}},
		ProtectedNetworks: []string{"10.99.0.0/16"}, Workers: workers, MaxDeviceSessions: workers, OperationTimeoutMillis: 5000, IdleTimeoutSeconds: 60,
	}
	encoded, err := json.Marshal(file)
	must(t, err)
	configPath := filepath.Join(dir, "config.json")
	must(t, os.WriteFile(configPath, encoded, 0600))
	if _, err := connector.LoadConfig(configPath); err != nil {
		t.Fatalf("protected valid config rejected: %v", err)
	}
	return configPath, file, client
}

func TestWorkloadGuestConfiguredConnectorCommand(t *testing.T) {
	v := newWorkloadFixture(t) // Enforces NIC-less Linux guest before any destination/socket work.
	v.server.Close()
	must(t, v.carrier.connector.Close())
	configPath, file, _ := guestConnectorConfiguration(t, v, 1)

	// A real CLI invocation must refuse the unsynchronized native guest clock.
	output, err := exec.Command("/portico", "connector", "run", "--config", configPath).CombinedOutput()
	if err == nil || string(output) != "Trusted clock health is unavailable.\n" {
		t.Fatalf("unsynchronized CLI: %v %q", err, output)
	}
	if v.carrier.relay.Stats().Waiting != 0 || v.connections.Load() != 0 {
		t.Fatal("unsynchronized CLI opened transport/destination")
	}
	must(t, os.Chmod(file.IdentityKeyFile, 0644))
	output, err = exec.Command("/portico", "connector", "run", "--config", configPath).CombinedOutput()
	if err == nil || string(output) != "Connector configuration rejected.\n" {
		t.Fatalf("unsafe key permission CLI: %v %q", err, output)
	}
	must(t, os.Chmod(file.IdentityKeyFile, 0600))

	guestSynchronizedClockFixture(t)
	seen := map[string]bool{}
	for round, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL, syscall.SIGTERM} {
		root, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(root, "/portico", "connector", "run", "--config", configPath)
		var logs bytes.Buffer
		command.Stdout = &logs
		command.Stderr = &logs
		must(t, command.Start())
		stopped := make(chan error, 1)
		go func() { stopped <- command.Wait() }()
		joined := false
		t.Cleanup(func() {
			cancel()
			if !joined {
				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Error("CLI fixture process did not join")
				}
			}
		})
		carrierEventually(t, func() bool { return v.carrier.relay.Stats().Waiting == 1 })
		c := openThroughRuntime(t, v)
		if seen[c.SessionID()] {
			t.Fatal("restart reused an old session")
		}
		seen[c.SessionID()] = true
		runtimeEcho(t, c)
		must(t, command.Process.Signal(signal))
		select {
		case err := <-stopped:
			joined = true
			if signal == syscall.SIGTERM && err != nil {
				t.Fatalf("SIGTERM exit: %v %q", err, logs.String())
			}
			if signal == syscall.SIGKILL && err == nil {
				t.Fatal("SIGKILL unexpectedly returned success")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("signal did not join connector process")
		}
		cancel()
		want := "Connector runtime stopped.\n"
		if signal == syscall.SIGKILL {
			want = ""
		}
		if logs.String() != want {
			t.Fatalf("unexpected CLI output %q", logs.String())
		}
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("terminated process retained client stream")
		}
		if _, err := c.Write([]byte("old session")); err == nil {
			t.Fatal("terminated stream accepted forwarding")
		}
		carrierEventually(t, func() bool { return v.closed.Load() == int64(round+1) && v.carrier.relay.Stats().Waiting == 0 })
	}
}

func guestSynchronizedClockFixture(t *testing.T) {
	t.Helper()
	requireWorkloadGuest(t)
	// Synthetic synchronization metadata changes only the disposable kernel,
	// never UTC or the host. This proves wiring, not upstream time accuracy.
	var original unix.Timex
	state, err := unix.Adjtimex(&original)
	must(t, err)
	if state != unix.TIME_ERROR || original.Status&unix.STA_UNSYNC == 0 {
		t.Fatal("guest clock was not initially unsynchronized")
	}
	fixture := unix.Timex{Modes: unix.ADJ_STATUS | unix.ADJ_MAXERROR | unix.ADJ_ESTERROR, Status: 0, Maxerror: 20000, Esterror: 10}
	_, err = unix.Adjtimex(&fixture)
	must(t, err)
	t.Cleanup(func() {
		restore := unix.Timex{Modes: unix.ADJ_STATUS | unix.ADJ_MAXERROR | unix.ADJ_ESTERROR, Status: original.Status, Maxerror: original.Maxerror, Esterror: original.Esterror}
		if _, err := unix.Adjtimex(&restore); err != nil {
			t.Errorf("restore guest clock metadata: %v", err)
		}
		if _, err := clockhealth.Uncertainty(); err == nil {
			t.Error("guest unsynchronized state was not restored")
		}
	})
	bound, err := clockhealth.Uncertainty()
	must(t, err)
	t.Logf("positive CLI fixture uses synthetic guest kernel synchronization metadata, native bound=%v", bound)
}
