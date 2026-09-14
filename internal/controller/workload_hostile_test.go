package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/wire"
	"portico.local/portico/internal/workload"
)

// PROTO-04 composes malformed enrollment/control input and actual hostile
// carrier/inner-TLS frames with an independent authorized TCP stream. All
// destination sockets remain in the explicitly guarded NIC-less guest.
func TestWorkloadGuestHostileProtocolInputs(t *testing.T) {
	requireWorkloadGuest(t)
	v := newWorkloadFixtureWithCarrier(t, echoWorkloadDestination, hostileCarrierLimits)
	anchor, served := v.open(t)
	runtimeEcho(t, anchor)
	var expectedSessions int64 = 1
	var expectedBytes int64 = int64(len("runtime"))
	healthy := func(t *testing.T) {
		t.Helper()
		carrierEventually(t, func() bool {
			return v.server.Stats() == (workload.Stats{Connections: 1}) && v.closed.Load() == expectedSessions-1
		})
		var sessions int64
		must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM authorized_sessions").Scan(&sessions))
		if sessions != expectedSessions || v.connections.Load() != expectedSessions || v.received.Load() != expectedBytes {
			t.Fatal("hostile traffic created unexpected authority, destination connections or application bytes")
		}
		runtimeEcho(t, anchor)
		expectedBytes += int64(len("runtime"))
	}
	t.Run("csr_enrollment", func(t *testing.T) { hostileCSREnrollment(t); healthy(t) })
	t.Run("https_bodies", func(t *testing.T) { hostilePolicyBodies(t); healthy(t) })
	t.Run("http2_carrier", func(t *testing.T) { hostileHTTP2Carrier(t, v.carrier, healthy) })

	valid, e := json.Marshal(struct {
		Version    int
		ResourceID string
		Revision   int64
	}{1, v.resource.ID, v.resource.Revision})
	must(t, e)
	message := func(size uint32, body []byte) []byte {
		b := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(b, size)
		copy(b[4:], body)
		return b
	}
	mutations := []struct {
		name string
		data []byte
	}{
		{"zero_length", message(0, nil)},
		{"over_limit", message(1025, nil)},
		{"maximum_length", message(^uint32(0), nil)},
		{"partial_header", []byte{0, 0}},
		{"truncated_body", message(uint32(len(valid)), valid[:len(valid)-1])},
		{"extra_document", message(uint32(len(valid)+2), append(bytes.Clone(valid), '{', '}'))},
	}
	var fields map[string]json.RawMessage
	must(t, json.Unmarshal(valid, &fields))
	for _, field := range []string{"Version", "ResourceID", "Revision"} {
		for _, alias := range []string{field, strings.ToLower(field), fmt.Sprintf(`\u%04x%s`, field[0], field[1:])} {
			b := []byte(strings.TrimSuffix(string(valid), "}") + `,"` + alias + `":` + string(fields[field]) + `}`)
			mutations = append(mutations, struct {
				name string
				data []byte
			}{"duplicate_" + alias, message(uint32(len(b)), b)})
		}
	}
	for _, mutation := range mutations {
		t.Run("inner_open_"+mutation.name, func(t *testing.T) {
			inner, device, connector, done := hostileWorkloadPeer(t, v)
			n, e := inner.Write(mutation.data)
			must(t, e)
			if n != len(mutation.data) {
				t.Fatal("hostile inner frame was not completely sent")
			}
			// Complete truncated inputs with actual TLS EOF; a local read timeout
			// cannot qualify rejection or stand in for server cleanup.
			_ = inner.CloseWrite()
			hostileWorkloadEnded(t, inner, device, connector, done)
			healthy(t)
		})
	}
	for _, frame := range []struct {
		name string
		kind byte
		size uint32
	}{
		{"unknown_kind", 255, 0}, {"zero_data", 1, 0}, {"oversized_data", 1, 32769},
		{"maximum_data", 1, ^uint32(0)}, {"fin_with_body", 2, 1},
		{"ack_with_body", 3, 1}, {"ack_before_fin", 3, 0},
	} {
		t.Run("payload_"+frame.name, func(t *testing.T) {
			inner, device, connector, done := hostileWorkloadPeer(t, v)
			_, e := inner.Write(message(uint32(len(valid)), valid))
			must(t, e)
			var head [4]byte
			_, e = io.ReadFull(inner, head[:])
			must(t, e)
			size := binary.BigEndian.Uint32(head[:])
			if size == 0 || size > 1024 {
				t.Fatal("invalid workload ready size")
			}
			body := make([]byte, size)
			_, e = io.ReadFull(inner, body)
			must(t, e)
			var ready struct {
				Version               int
				SessionID, ResourceID string
				Revision              int64
			}
			must(t, wire.Decode(body, &ready))
			if ready.Version != 1 || ready.ResourceID != v.resource.ID || ready.Revision != v.resource.Revision || ready.SessionID == anchor.SessionID() {
				t.Fatal("wrong positive workload authority")
			}
			expectedSessions++ // The valid open, before the malformed payload, is authorized.
			var poison [5]byte
			poison[0] = frame.kind
			binary.BigEndian.PutUint32(poison[1:], frame.size)
			_, e = inner.Write(poison[:])
			must(t, e)
			hostileWorkloadEnded(t, inner, device, connector, done)
			healthy(t)
		})
	}
	must(t, anchor.Close())
	select {
	case <-anchor.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("independent workload did not join")
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("independent workload server did not join")
	}
	carrierEventually(t, func() bool {
		s := v.carrier.relay.Stats()
		return v.closed.Load() == expectedSessions && v.server.Stats() == (workload.Stats{}) && v.client.ActiveConnections() == 0 && s.Streams == 0 && s.Waiting == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0
	})
	var receipts int64
	must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts").Scan(&receipts))
	if receipts != expectedSessions {
		t.Fatal("ended authorized sessions lack closure receipts")
	}
	t.Logf("PROTO-04: 15 malformed opens, 7 malformed payloads, 9 gRPC mutations, 24 actual resets plus CSR/HTTPS corpus; %d deliberately authorized destinations and receipts; independent stream survived, all workers joined", expectedSessions)
}

func hostileWorkloadPeer(t *testing.T, v *workloadFixture) (*tls.Conn, *carrier.Conn, *carrier.Conn, <-chan error) {
	t.Helper()
	device, connector := v.carrier.pair(t, ctx)
	done := make(chan error, 1)
	go func() { done <- v.server.Serve(ctx, connector) }()
	config, e := v.carrier.policy.connector.trust.ConnectorClientTLS(v.carrier.deviceConfig.Identity, v.resource.ConnectorID)
	must(t, e)
	inner := tls.Client(device, config)
	t.Cleanup(func() { _ = inner.Close() })
	must(t, inner.SetDeadline(time.Now().Add(5*time.Second)))
	must(t, inner.HandshakeContext(ctx))
	if !bytes.Equal(inner.ConnectionState().PeerCertificates[0].Raw, v.carrier.policy.connectorLeaf) {
		t.Fatal("wrong inner connector identity")
	}
	return inner, device, connector, done
}

func hostileWorkloadEnded(t *testing.T, inner *tls.Conn, device, connector *carrier.Conn, done <-chan error) {
	t.Helper()
	var b [1]byte
	n, e := inner.Read(b[:])
	if n != 0 || e == nil {
		t.Fatal("malformed input returned workload payload")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("local timeout substituted for peer rejection")
	}
	select {
	case e := <-done:
		if e != workload.ErrDenied {
			t.Fatalf("hostile workload ended without explicit denial: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hostile workload server retained workers")
	}
	// Verify server-driven termination before closing the local fixture.
	carrierStopped(t, device, connector)
	_ = inner.Close()
}
