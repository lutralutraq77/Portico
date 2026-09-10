//go:build linux

package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

// Manual pipes keep Wait from closing the reader before the application has
// consumed the final response. They also model inherited blocking child FDs.
type guestApplication struct {
	command       *exec.Cmd
	input, output *os.File
	logs          bytes.Buffer
	done          chan struct{}
	err           error // Read only after done, which joins Wait and its stderr copier.
}

func guestStartApplication(t *testing.T, args ...string) *guestApplication {
	t.Helper()
	return guestStartApplicationWithFiles(t, nil, args...)
}

func guestStartApplicationWithFiles(t *testing.T, files []*os.File, args ...string) *guestApplication {
	t.Helper()
	requireWorkloadGuest(t)
	root, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	v := &guestApplication{command: exec.CommandContext(root, "/portico", args...), done: make(chan struct{})}
	v.command.ExtraFiles = files
	childInput, input, err := os.Pipe()
	must(t, err)
	output, childOutput, err := os.Pipe()
	must(t, err)
	v.input, v.output = input, output
	v.command.Stdin, v.command.Stdout, v.command.Stderr = childInput, childOutput, &v.logs
	err = v.command.Start()
	_ = childInput.Close()
	_ = childOutput.Close()
	if err != nil {
		cancel()
		_ = input.Close()
		_ = output.Close()
		t.Fatal(err)
	}
	go func() { v.err = v.command.Wait(); close(v.done) }()
	t.Cleanup(func() {
		cancel()
		_ = input.Close()
		_ = output.Close()
		select {
		case <-v.done:
			if t.Failed() {
				t.Logf("fixture process exit=%v stderr=%q", v.err, v.logs.String())
			}
		case <-time.After(5 * time.Second):
			t.Error("application fixture did not join")
		}
	})
	return v
}

func (v *guestApplication) ended(t *testing.T, success bool, message string) {
	t.Helper()
	select {
	case <-v.done:
		if (v.err == nil) != success || v.logs.String() != message {
			t.Fatalf("application exit=%v stderr=%q", v.err, v.logs.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application did not join while local I/O was blocked")
	}
}

func guestClientConfiguration(t *testing.T, v *workloadFixture, connectorPath string, setup ...func(*PolicyHTTPServer)) (string, client.FileConfig) {
	t.Helper()
	p := v.carrier.policy
	_, endpoint := serveControlClient(t, p, pki.Device, setup...)
	encoded, err := os.ReadFile(connectorPath)
	must(t, err)
	var connectorFile struct {
		Devices, Connectors client.TrustFiles
	}
	must(t, json.Unmarshal(encoded, &connectorFile))
	write := func(name, kind string, der []byte) string {
		path := filepath.Join(filepath.Dir(connectorPath), name)
		must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600))
		return path
	}
	key, err := x509.MarshalPKCS8PrivateKey(p.deviceIdentity.PrivateKey)
	must(t, err)
	defer clear(key)
	file := client.FileConfig{
		Version: 1, DeploymentID: p.device.config.DeploymentID,
		Devices: connectorFile.Devices, Connectors: connectorFile.Connectors,
		IdentityCertificateFile: write("client-identity.pem", "CERTIFICATE", p.deviceLeaf),
		IdentityKeyFile:         write("client-key.pem", "PRIVATE KEY", key),
		Control:                 client.EndpointFiles{URL: endpoint.Endpoint, RootCertificateFile: write("client-control.pem", "CERTIFICATE", endpoint.ServerRootDER), SPKI: endpoint.ServerSPKI},
		Carrier:                 client.EndpointFiles{URL: v.carrier.deviceConfig.Endpoint, RootCertificateFile: write("client-carrier.pem", "CERTIFICATE", v.carrier.deviceConfig.ServerRootDER), SPKI: v.carrier.deviceConfig.ServerSPKI},
		OperationTimeoutMillis:  5000, IdleTimeoutSeconds: 60,
	}
	encoded, err = json.Marshal(file)
	must(t, err)
	path := filepath.Join(filepath.Dir(connectorPath), "client.json")
	must(t, os.WriteFile(path, encoded, 0600))
	_, err = client.LoadConfig(path)
	must(t, err)
	return path, file
}

func TestWorkloadGuestConfiguredClientCommand(t *testing.T) {
	request := bytes.Repeat([]byte("client-request-"), 8192)
	response := func(n int) []byte { return bytes.Repeat([]byte{0x41, 0, 0xfe, 0x0a}, (n+3)/4)[:n] }
	var produced atomic.Int64
	v := newWorkloadFixtureWithCarrier(t, func(c net.Conn) {
		var header [5]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return
		}
		switch header[0] {
		case 'F':
			n := int(binary.BigEndian.Uint32(header[1:]))
			if n < 1 || n > 1<<20 {
				return
			}
			got, err := io.ReadAll(io.LimitReader(c, int64(len(request)+1)))
			if err != nil || !bytes.Equal(got, request) {
				return
			}
			_, _ = c.Write(response(n)) // The response exists only after request EOF.
		case 'R':
			echoWorkloadDestination(c)
		case 'W':
			chunk := bytes.Repeat([]byte{0x57}, 32768)
			for i := 0; i < 2048; i++ {
				n, err := c.Write(chunk)
				produced.Add(int64(n))
				if err != nil {
					return
				}
			}
		}
	}, func(config *carrier.Config) { config.MaxLifetime = 2 * time.Minute })
	v.server.Close()
	must(t, v.carrier.connector.Close())
	connectorPath, connectorFile, _ := guestConnectorConfiguration(t, v, 1)
	path, file := guestClientConfiguration(t, v, connectorPath)
	args := func(id string, revision int64) []string {
		return []string{"client", "connect", "--config", path, "--resource", id, "--revision", strconv.FormatInt(revision, 10)}
	}
	catalogArgs := []string{"client", "catalog", "--config", path}
	output, err := exec.Command("/portico", catalogArgs...).CombinedOutput()
	if err == nil || string(output) != "Trusted clock health is unavailable.\n" {
		t.Fatalf("unsynchronized client: %v %q", err, output)
	}
	must(t, os.Chmod(file.IdentityKeyFile, 0644))
	output, err = exec.Command("/portico", catalogArgs...).CombinedOutput()
	if err == nil || string(output) != "Client configuration rejected.\n" {
		t.Fatalf("unsafe client key: %v %q", err, output)
	}
	must(t, os.Chmod(file.IdentityKeyFile, 0600))
	if v.connections.Load() != 0 || v.carrier.relay.Stats().Waiting != 0 {
		t.Fatal("rejected startup opened transport")
	}

	guestSynchronizedClockFixture(t)
	connectorProcess := guestStartApplication(t, "connector", "run", "--config", connectorPath)
	carrierEventually(t, func() bool { return v.carrier.relay.Stats().Waiting == 1 })
	output, err = exec.Command("/portico", catalogArgs...).CombinedOutput()
	must(t, err)
	var catalog control.CatalogSnapshot
	must(t, json.Unmarshal(output, &catalog))
	found := false
	for _, r := range catalog.Resources {
		if r.ID == v.resource.ID {
			found = r.Revision == v.resource.Revision && r.ConnectorID == v.resource.ConnectorID && r.Address == v.resource.Address && r.Port == v.resource.Port && r.Protocol == "tcp"
		}
	}
	if catalog.Version != 1 || !found {
		t.Fatal("real client catalog omitted exact resource tuple")
	}

	assertNoAuthority := func(t *testing.T) {
		t.Helper()
		var sessions int
		must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&sessions))
		if sessions != 0 || v.connections.Load() != 0 {
			t.Fatal("rejected client changed authority or destination count")
		}
	}
	for _, selection := range []struct {
		name, id string
		revision int64
	}{
		{"unknown_resource", NewID(), 1}, {"future_revision", v.resource.ID, v.resource.Revision + 1},
	} {
		t.Run(selection.name, func(t *testing.T) {
			p := guestStartApplication(t, args(selection.id, selection.revision)...)
			p.ended(t, false, "Client resource connection failed.\n")
			assertNoAuthority(t)
		})
	}
	original, err := os.ReadFile(path)
	must(t, err)
	for _, mutation := range []string{"destination", "username", "clock_override", "connector_identity"} {
		t.Run(mutation, func(t *testing.T) {
			var value map[string]any
			must(t, json.Unmarshal(original, &value))
			if mutation == "connector_identity" {
				value["identity_certificate_file"], value["identity_key_file"] = connectorFile.IdentityCertificateFile, connectorFile.IdentityKeyFile
			} else {
				value[mutation] = "synthetic-untrusted-override"
			}
			body, e := json.Marshal(value)
			must(t, e)
			must(t, os.WriteFile(path, body, 0600))
			t.Cleanup(func() { must(t, os.WriteFile(path, original, 0600)) })
			p := guestStartApplication(t, args(v.resource.ID, v.resource.Revision)...)
			p.ended(t, false, "Client configuration rejected.\n")
			assertNoAuthority(t)
		})
	}
	var sessions int64
	startClient := func(t *testing.T) *guestApplication {
		t.Helper()
		// Bindings deliberately expire while idle. Wait for a newly admitted
		// binding, rather than racing a snapshot near its pairing deadline.
		before := v.carrier.admitted.Load()
		deadline := time.NewTimer(8 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-connectorProcess.done:
				t.Fatalf("connector exited before application open: %v %q", connectorProcess.err, connectorProcess.logs.String())
			case <-deadline.C:
				t.Fatal("connector did not establish a fresh fixture binding")
			case <-tick.C:
				if v.carrier.admitted.Load() > before && v.carrier.relay.Stats().Waiting == 1 {
					return guestStartApplication(t, args(v.resource.ID, v.resource.Revision)...)
				}
			}
		}
	}
	closed := func(t *testing.T) {
		t.Helper()
		carrierEventually(t, func() bool {
			select {
			case <-connectorProcess.done:
				t.Fatalf("connector exited before closure receipt: %v %q", connectorProcess.err, connectorProcess.logs.String())
			default:
			}
			var receipts int64
			return v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts) == nil && receipts == sessions && v.closed.Load() == sessions
		})
	}
	for _, consume := range []bool{true, false} {
		name := "final_response_after_input_eof_and_carrier_close"
		if !consume {
			name = "final_response_drain_deadline"
		}
		t.Run(name, func(t *testing.T) {
			p := startClient(t)
			var pipeSize int
			raw, e := p.output.SyscallConn()
			must(t, e)
			must(t, raw.Control(func(fd uintptr) { pipeSize, e = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0) }))
			must(t, e)
			responseSize := pipeSize + 16384
			var header [5]byte
			header[0] = 'F'
			binary.BigEndian.PutUint32(header[1:], uint32(responseSize))
			must(t, p.input.SetWriteDeadline(time.Now().Add(10*time.Second)))
			_, e = p.input.Write(append(header[:], request...))
			must(t, e)
			must(t, p.input.Close())
			sessions++
			closed(t) // Peer FIN/ACK and closure receipt while stdout remains unread.
			select {
			case <-p.done:
				t.Fatalf("client abandoned buffered final response: %v %q", p.err, p.logs.String())
			default:
			}
			if !consume {
				select {
				case <-p.done:
				case <-time.After(6 * time.Second):
					t.Fatal("final response drain ignored its five-second deadline")
				}
				p.ended(t, false, "Client resource connection failed.\n")
				return
			}
			must(t, p.output.SetReadDeadline(time.Now().Add(5*time.Second)))
			got, e := io.ReadAll(io.LimitReader(p.output, int64(responseSize+1)))
			must(t, e)
			if !bytes.Equal(got, response(responseSize)) {
				t.Fatalf("final response bytes=%d want=%d", len(got), responseSize)
			}
			p.ended(t, true, "")
			t.Logf("request=%d response=%d pipe_capacity=%d; receipt before application drain, exact bytes and successful exit", len(request), responseSize, pipeSize)
		})
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(signal.String()+"_idle_input", func(t *testing.T) {
			p := startClient(t)
			must(t, p.input.SetWriteDeadline(time.Now().Add(10*time.Second)))
			_, e := p.input.Write([]byte{'R', 0, 0, 0, 0, 'o', 'k'})
			must(t, e)
			must(t, p.output.SetReadDeadline(time.Now().Add(10*time.Second)))
			var echo [2]byte
			_, e = io.ReadFull(p.output, echo[:])
			must(t, e)
			if string(echo[:]) != "ok" {
				t.Fatal("wrong application echo")
			}
			sessions++
			must(t, p.command.Process.Signal(signal))
			message := "Client resource connection failed.\n"
			if signal == syscall.SIGKILL {
				message = ""
			}
			p.ended(t, false, message)
			closed(t)
		})
	}
	t.Run("revocation_with_blocked_output", func(t *testing.T) {
		p := startClient(t)
		must(t, p.input.SetWriteDeadline(time.Now().Add(10*time.Second)))
		_, e := p.input.Write([]byte{'W', 0, 0, 0, 0})
		must(t, e)
		raw, e := p.output.SyscallConn()
		must(t, e)
		var capacity int
		must(t, raw.Control(func(fd uintptr) { capacity, e = unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0) }))
		must(t, e)
		carrierEventually(t, func() bool {
			var queued int
			must(t, raw.Control(func(fd uintptr) { queued, e = unix.IoctlGetInt(int(fd), unix.TIOCINQ) }))
			must(t, e)
			return queued == capacity && produced.Load() > int64(capacity+32768)
		})
		sessions++
		f := v.carrier.policy.device.f
		must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", v.grant.ID) }))
		p.ended(t, false, "Client resource connection failed.\n") // No reader to relieve backpressure.
		closed(t)
		must(t, p.output.SetReadDeadline(time.Now().Add(time.Second)))
		queued, e := io.ReadAll(io.LimitReader(p.output, 1<<20))
		must(t, e)
		if len(queued) != capacity {
			t.Fatal("closed application pipe retained unexpected output")
		}
		t.Logf("revocation joined blocked process; %d previously queued pipe bytes drained after exit", len(queued))
		denied := guestStartApplication(t, args(v.resource.ID, v.resource.Revision)...)
		denied.ended(t, false, "Client resource connection failed.\n")
		if v.connections.Load() != sessions {
			t.Fatal("new process reused revoked access")
		}
	})
	must(t, connectorProcess.command.Process.Signal(syscall.SIGTERM))
	connectorProcess.ended(t, true, "")
	t.Logf("development client: exact catalog, six denials without authority, %d application sessions and closure receipts, EOF/signals/revocation exercised", sessions)
}
