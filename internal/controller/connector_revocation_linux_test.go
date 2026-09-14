//go:build linux

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/workload"
)

type guestConnectorProcess struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	done    chan error
	logs    bytes.Buffer
	joined  bool
}

func startGuestConnectorProcess(t *testing.T, path string) *guestConnectorProcess {
	t.Helper()
	requireWorkloadGuest(t)
	call, cancel := context.WithTimeout(ctx, time.Minute)
	p := &guestConnectorProcess{cancel: cancel, done: make(chan error, 1)}
	p.command = exec.CommandContext(call, "/portico", "connector", "run", "--config", path)
	p.command.Stdout, p.command.Stderr = &p.logs, &p.logs
	must(t, p.command.Start())
	go func() { p.done <- p.command.Wait() }()
	t.Cleanup(func() {
		cancel()
		if !p.joined {
			select {
			case <-p.done:
				p.joined = true
			case <-time.After(5 * time.Second):
				t.Error("connector process did not join during cleanup")
			}
		}
		if t.Failed() && p.joined {
			t.Logf("connector process output after joining: %q", p.logs.String())
		}
	})
	return p
}

func (p *guestConnectorProcess) requireRunning(t *testing.T) {
	t.Helper()
	select {
	case e := <-p.done:
		p.joined = true
		t.Fatalf("connector process exited early: %v %q", e, p.logs.String())
	default:
	}
}

func (p *guestConnectorProcess) stop(t *testing.T) {
	t.Helper()
	p.requireRunning(t)
	must(t, p.command.Process.Signal(syscall.SIGTERM))
	select {
	case e := <-p.done:
		p.joined = true
		must(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not join revoked connector process")
	}
	p.cancel()
	if p.logs.String() != "Connector runtime stopped.\n" {
		t.Fatalf("unexpected connector process output: %q", p.logs.String())
	}
}

type revocationTraffic struct {
	rounds  atomic.Int64
	done    chan struct{}
	err     error
	corrupt bool
}

func startRevocationTraffic(t *testing.T, c *workload.Conn, pattern byte) *revocationTraffic {
	t.Helper()
	p := &revocationTraffic{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		payload := bytes.Repeat([]byte{pattern}, 4096)
		response := make([]byte, len(payload))
		for {
			if p.err = c.SetDeadline(time.Now().Add(3 * time.Second)); p.err != nil {
				return
			}
			var n int
			if n, p.err = c.Write(payload); p.err != nil {
				return
			}
			if n != len(payload) {
				p.err, p.corrupt = io.ErrShortWrite, true
				return
			}
			if _, p.err = io.ReadFull(c, response); p.err != nil {
				return
			}
			if !bytes.Equal(payload, response) {
				p.corrupt = true
				return
			}
			p.rounds.Add(1)
			time.Sleep(10 * time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		_ = c.Close()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("traffic fixture did not join")
		}
	})
	return p
}

type hostingObservation struct {
	workload.ConnectorControl
	calls atomic.Int64
}

func (h *hostingObservation) Hosting(call context.Context) (control.HostingSnapshot, error) {
	h.calls.Add(1)
	return h.ConnectorControl.Hosting(call)
}

// CONN-04 combines live traffic, both revocation kinds, actual binary restart,
// saved resource/session replays and a separate still-authorized connector.
func TestWorkloadGuestConnectorRevocationRestartAndReplay(t *testing.T) {
	for _, kind := range []string{"connector", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			v := newWorkloadFixture(t)
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("carrier diagnostics: %+v admissions=%d rejections=%d destination accepts=%d closes=%d", v.carrier.relay.Stats(), v.carrier.admitted.Load(), v.carrier.rejected.Load(), v.connections.Load(), v.closed.Load())
				}
			})
			v.server.Close()
			must(t, v.carrier.connector.Close())
			p, f := v.carrier.policy, v.carrier.policy.device.f
			configPath, file, aControl := guestConnectorConfiguration(t, v, 2)
			originalConfig, e := os.ReadFile(configPath)
			must(t, e)
			guestSynchronizedClockFixture(t)
			serverFor := func(client workload.ConnectorControl, identity tls.Certificate, cert string, r Resource) *workload.Server {
				s, e := workload.NewServer(ctx, workload.ServerConfig{
					Control: client, Devices: p.device.trust, Connectors: p.connector.trust,
					Identity: identity, CertificateID: cert,
					Approved:          []workload.Destination{{ResourceID: r.ID, Revision: r.Revision, Address: r.Address, Port: r.Port, Protocol: r.Protocol}},
					ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
					MaxSessions:       2, MaxDeviceSessions: 2, OperationTimeout: 5 * time.Second, IdleTimeout: time.Minute,
					ClockHealth: func() (time.Duration, error) { return 20 * time.Millisecond, nil },
				})
				must(t, e)
				t.Cleanup(s.Close)
				return s
			}

			// B shares the controller and device, but has its own real enrolled
			// certificate, resource and HostBinding. Keep its connection alive
			// while both A sessions lose authority.
			b := secondConnector(t, p)
			rB := connectorResource(t, p, b, v.resource, true)
			carrierConfig := v.carrier.connectorConfig
			carrierConfig.Identity = b.identity
			bCarrier, e := carrier.NewClient(carrierConfig)
			must(t, e)
			t.Cleanup(func() { _ = bCarrier.Close() })
			bServer := serverFor(b.control, b.identity, b.certID, rB)
			deviceRaw, bRaw := pairConnector(t, v.carrier, bCarrier, b.connector.ID)
			bServed := make(chan error, 1)
			go func() { bServed <- bServer.Serve(ctx, bRaw) }()
			bConn, e := v.client.Open(ctx, deviceRaw, control.ResourceAccess{ID: rB.ID, Revision: rB.Revision, ConnectorID: rB.ConnectorID, Address: rB.Address, Port: rB.Port, Protocol: rB.Protocol})
			must(t, e)
			t.Cleanup(func() { _ = bConn.Close() })
			runtimeEcho(t, bConn)

			process := startGuestConnectorProcess(t, configPath)
			carrierEventually(t, func() bool {
				process.requireRunning(t)
				return v.carrier.relay.Stats().Waiting == 2
			})
			type opened struct {
				c   *workload.Conn
				err error
			}
			results := make(chan opened, 2)
			for i := 0; i < 2; i++ {
				go func() { c, e := tryOpenThroughRuntime(v); results <- opened{c, e} }()
			}
			var sessions []*workload.Conn
			var traffic []*revocationTraffic
			for i := 0; i < 2; i++ {
				select {
				case r := <-results:
					if r.err != nil {
						process.requireRunning(t)
						t.Fatalf("initial workload connection rejected while connector remained running: %v; relay=%+v; destination accepts=%d closes=%d", r.err, v.carrier.relay.Stats(), v.connections.Load(), v.closed.Load())
					}
					t.Cleanup(func() { _ = r.c.Close() })
					sessions = append(sessions, r.c)
					traffic = append(traffic, startRevocationTraffic(t, r.c, byte(0x41+i)))
				case <-time.After(8 * time.Second):
					t.Fatal("both process sessions did not open")
				}
			}
			if sessions[0].SessionID() == sessions[1].SessionID() {
				t.Fatal("distinct process connections shared one session")
			}
			carrierEventually(t, func() bool { return traffic[0].rounds.Load() >= 2 && traffic[1].rounds.Load() >= 2 })
			snapshot, e := aControl.Hosting(ctx)
			must(t, e)
			var cached control.HostingResource
			for _, item := range snapshot.Resources {
				if item.Resource.ID == v.resource.ID {
					cached = item
				}
			}
			if cached.HostBindingID == "" || snapshot.ConnectorCertificateID != file.CertificateID {
				t.Fatal("missing real pre-revocation hosting state")
			}
			for _, p := range traffic {
				select {
				case <-p.done:
					t.Fatal("traffic stopped before the revocation trigger")
				default:
				}
			}
			type savedLease struct {
				request control.SessionRequest
				until   int64
			}
			leases := make([]savedLease, len(sessions))
			target := f.connector.ID
			if kind == "certificate" {
				target = file.CertificateID
			}
			start := time.Now()
			must(t, f.s.Update(ctx, f.actor, func(tx *Tx) error {
				// Capture the last accepted sequence in the same transaction as
				// revocation, preventing a concurrent renewal from changing it.
				for i, c := range sessions {
					leases[i].request = control.SessionRequest{Version: 1, SessionID: c.SessionID()}
					var ledger, authority string
					if e := tx.tx.QueryRowContext(ctx, `SELECT s.state,a.state,a.lease_sequence,a.lease_until FROM sessions s JOIN authorized_sessions a ON a.id=s.id WHERE s.id=? AND a.connector_id=? AND s.connector_certificate_id=?`, c.SessionID(), f.connector.ID, file.CertificateID).Scan(&ledger, &authority, &leases[i].request.Sequence, &leases[i].until); e != nil {
						return e
					}
					if ledger != "requested" || authority != "active" || leases[i].until <= tx.now.UnixNano() {
						return ErrInvalid
					}
				}
				return tx.Disable(kind, target)
			}))
			denyReplays := func(beforeExpiry bool) {
				for _, lease := range leases {
					if beforeExpiry && time.Now().UnixNano() >= lease.until {
						t.Fatal("fixture lost the still-live cached lease precondition")
					}
					if _, e := aControl.Renew(ctx, lease.request); e == nil {
						t.Fatal("revoked connector renewed a prior session")
					}
					if _, e := aControl.Activate(ctx, control.SessionRequest{Version: 1, SessionID: lease.request.SessionID, Sequence: 1}); e == nil {
						t.Fatal("revoked connector replayed original activation")
					}
				}
				if _, e := aControl.Authorize(ctx, control.AuthorizeRequest{Version: 1, ClientLeafDER: p.deviceLeaf, ResourceID: cached.Resource.ID, Revision: cached.Resource.Revision}); e == nil {
					t.Fatal("cached hosting state authorized new access after revocation")
				}
				if _, e := aControl.Hosting(ctx); e == nil {
					t.Fatal("revoked connector refreshed hosting state")
				}
			}
			denyReplays(true)
			for i, c := range sessions {
				select {
				case <-c.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("dependent client stream survived revocation")
				}
				select {
				case <-traffic[i].done:
					if traffic[i].err == nil || traffic[i].corrupt {
						t.Fatal("traffic ended without closure or changed payload")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("revoked forwarding traffic did not join")
				}
				if _, e := c.Write([]byte("old stream")); e == nil {
					t.Fatal("revoked stream still forwarded")
				}
			}
			carrierEventually(t, func() bool { return v.closed.Load() == 2 })
			t.Logf("both dependent destination connections closed after %v; fixture observation only", time.Since(start))
			runtimeEcho(t, bConn)
			var bState string
			must(t, f.s.db.QueryRow("SELECT state FROM authorized_sessions WHERE id=?", bConn.SessionID()).Scan(&bState))
			if bState != "active" {
				t.Fatal("unrelated connector session lost authority")
			}
			must(t, bConn.Close())
			select {
			case <-bServed:
			case <-time.After(5 * time.Second):
				t.Fatal("unrelated connector did not join its later explicit close")
			}
			carrierStopped(t, deviceRaw, bRaw)
			carrierEventually(t, func() bool { return v.closed.Load() == 3 && bServer.Stats() == (workload.Stats{}) })
			process.stop(t)
			beforeRejected, beforeAdmitted := v.carrier.rejected.Load(), v.carrier.admitted.Load()
			beforeBytes := v.received.Load()
			restarted := startGuestConnectorProcess(t, configPath)
			// Observe actual rejected attempts and retries from the new binary;
			// an idle process that never loaded its config cannot pass this.
			carrierEventually(t, func() bool { return v.carrier.rejected.Load() >= beforeRejected+4 })
			restarted.requireRunning(t)
			if v.carrier.admitted.Load() != beforeAdmitted || v.carrier.relay.Stats().Waiting != 0 {
				t.Fatal("restart restored a revoked carrier binding")
			}
			denyReplays(false)

			// Bypass the revoked outer carrier gate to test the fresh workload
			// server independently. It gets the old snapshot's exact tuple and
			// original identity, but must consult the real live controller.
			r := v.resource
			r.ID, r.Revision, r.ConnectorID = cached.Resource.ID, cached.Resource.Revision, cached.Resource.ConnectorID
			r.Address, r.Port, r.Protocol = cached.Resource.Address, cached.Resource.Port, cached.Resource.Protocol
			observed := &hostingObservation{ConnectorControl: aControl}
			fresh := serverFor(observed, p.connectorIdentity, file.CertificateID, r)
			devicePipe, connectorPipe := net.Pipe()
			t.Cleanup(func() { _ = devicePipe.Close(); _ = connectorPipe.Close() })
			hostileInnerOpenDenied(t, v, devicePipe, connectorPipe, fresh, f.connector.ID, p.connectorLeaf, r)
			if observed.calls.Load() != 1 {
				t.Fatal("stale hosting replay did not reach live controller validation")
			}
			restarted.stop(t)
			currentConfig, e := os.ReadFile(configPath)
			must(t, e)
			if !bytes.Equal(originalConfig, currentConfig) {
				t.Fatal("restart changed the original protected configuration")
			}
			if v.connections.Load() != 3 || v.closed.Load() != 3 || v.received.Load() != beforeBytes {
				t.Fatal("prior hosting/session state resurrected destination access")
			}
			for _, lease := range leases {
				var ledger, authority string
				var sequence, until int64
				must(t, f.s.db.QueryRow(`SELECT s.state,a.state,a.lease_sequence,a.lease_until FROM sessions s JOIN authorized_sessions a ON a.id=s.id WHERE s.id=?`, lease.request.SessionID).Scan(&ledger, &authority, &sequence, &until))
				if ledger != "closed" || authority != "closed" || sequence != lease.request.Sequence || until > lease.until {
					t.Fatal("replay extended or resurrected a closed lease")
				}
			}
			var total, binding, grant int
			must(t, f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions WHERE connector_id=?", f.connector.ID).Scan(&total))
			must(t, f.s.db.QueryRow("SELECT enabled FROM host_bindings WHERE id=?", cached.HostBindingID).Scan(&binding))
			must(t, f.s.db.QueryRow("SELECT enabled FROM grants WHERE id=?", v.grant.ID).Scan(&grant))
			if total != 2 || binding != 1 || grant != 1 {
				t.Fatal("replay created a session or fixture revoked unrelated hosting/grant authority")
			}
			if _, e := b.control.Hosting(ctx); e != nil {
				t.Fatal("unrelated connector cannot refresh hosting after A restart")
			}
			carrierEventually(t, func() bool {
				s := v.carrier.relay.Stats()
				return s.Streams == 0 && s.Waiting == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0
			})
			must(t, verifyAudit(ctx, f.s.db))
			t.Log("CONN-04: both A sessions closed; B stayed authorized; actual process restart and original hosting/session replays opened no destination")
		})
	}
}
