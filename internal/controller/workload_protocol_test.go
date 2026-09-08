package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"portico.local/portico/internal/carrier"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/workload"
)

// PROTO-03: three complete inner-TLS/control/TCP streams share one connector
// runtime. Each has distinct position-tagged data and an independent ending.
func TestWorkloadGuestIndependentStreamLifecycles(t *testing.T) {
	var payloads [3][]byte
	for i := range payloads {
		// Exceed three DATA frames and include a non-aligned tail. Position
		// tags detect reordering as well as mixing data between streams.
		payload := make([]byte, 3*32768+17+i)
		for offset := 0; offset+8 <= len(payload); offset += 8 {
			binary.BigEndian.PutUint64(payload[offset:offset+8], uint64(i+1)<<48|uint64(offset))
		}
		payload[len(payload)-1] = byte(0x71 + i)
		payloads[i] = payload
	}
	tail := bytes.Repeat([]byte("A final ordered tail\x00"), 4099)
	tailReply := append(bytes.Clone(tail), []byte("A response created after request EOF\n")...)
	var requestFIN, postFINReply atomic.Bool
	v := newWorkloadFixtureWithDestination(t, func(c net.Conn) {
		var header [8]byte
		if _, e := io.ReadFull(c, header[:]); e != nil {
			return
		}
		id := binary.BigEndian.Uint64(header[:]) >> 48
		if id < 1 || id > uint64(len(payloads)) {
			t.Error("destination received an unknown stream's data")
			return
		}
		payload := payloads[id-1]
		got := make([]byte, len(payload))
		copy(got, header[:])
		if _, e := io.ReadFull(c, got[len(header):]); e != nil || !bytes.Equal(got, payload) {
			t.Error("destination received incomplete or reordered initial data")
			return
		}
		if _, e := c.Write(got); e != nil {
			return
		}
		if id != 1 {
			echoWorkloadDestination(c)
			return
		}
		// A's final response is withheld until the destination sees EOF.
		// A full close instead of a half-close cannot receive this response.
		got, e := io.ReadAll(io.LimitReader(c, int64(len(tail)+1)))
		if e != nil || !bytes.Equal(got, tail) {
			t.Error("destination did not receive the complete A request before EOF")
			return
		}
		requestFIN.Store(true)
		if n, e := c.Write(tailReply); e == nil && n == len(tailReply) {
			postFINReply.Store(true)
		}
	})
	stopRuntime, runtimeDone := startConnectorRuntime(t, v, 3)
	type stream struct {
		index  int
		cancel context.CancelFunc
		raw    *carrier.Conn
		conn   *workload.Conn
		err    error
	}
	opened := make(chan stream, 3)
	for i := 0; i < 3; i++ {
		call, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		go func(index int) {
			s := stream{index: index, cancel: cancel}
			r := v.resource
			s.raw, s.err = v.carrier.device.Dial(call, r.ConnectorID)
			if s.err == nil {
				s.conn, s.err = v.client.Open(call, s.raw, control.ResourceAccess{ID: r.ID, Revision: r.Revision, ConnectorID: r.ConnectorID, Address: r.Address, Port: r.Port, Protocol: r.Protocol})
			}
			opened <- s
		}(i)
	}
	var streams [3]stream
	sessionIDs := map[string]bool{}
	for i := 0; i < len(streams); i++ {
		select {
		case s := <-opened:
			must(t, s.err)
			t.Cleanup(func() { _ = s.conn.Close() })
			if sessionIDs[s.conn.SessionID()] {
				t.Fatal("independent streams shared a session ID")
			}
			sessionIDs[s.conn.SessionID()] = true
			streams[s.index] = s
		case <-time.After(8 * time.Second):
			t.Fatal("concurrent workload opens did not join")
		}
	}
	var expectedBytes int64
	type transfer struct {
		index int
		n     int
		err   error
	}
	writes, reads := make(chan transfer, 3), make(chan transfer, 3)
	for i, s := range streams {
		payload := payloads[i]
		expectedBytes += int64(len(payload))
		must(t, s.conn.SetDeadline(time.Now().Add(8*time.Second)))
		go func(index int, c *workload.Conn, payload []byte) {
			n, e := c.Write(payload)
			writes <- transfer{index, n, e}
		}(i, s.conn, payload)
		go func(index int, c *workload.Conn, payload []byte) {
			got := make([]byte, len(payload))
			n, e := io.ReadFull(c, got)
			if e == nil && !bytes.Equal(got, payload) {
				e = io.ErrUnexpectedEOF
			}
			reads <- transfer{index, n, e}
		}(i, s.conn, payload)
	}
	for _, results := range []<-chan transfer{writes, reads} {
		for i := 0; i < len(streams); i++ {
			select {
			case r := <-results:
				must(t, r.err)
				if r.n != len(payloads[r.index]) {
					t.Fatal("concurrent stream payload was truncated")
				}
			case <-time.After(8 * time.Second):
				t.Fatal("concurrent bidirectional transfer did not join")
			}
		}
	}
	for _, s := range streams {
		must(t, s.conn.SetDeadline(time.Time{}))
	}
	if v.connections.Load() != 3 || v.received.Load() != expectedBytes || v.closed.Load() != 0 {
		t.Fatal("initial stream transfer changed destination/socket counts")
	}
	waitClosed := func(c *workload.Conn, closed int64) {
		t.Helper()
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("ended workload stream did not join")
		}
		carrierEventually(t, func() bool { return v.closed.Load() == closed })
	}
	// Cancel only B's caller context. A and C must remain usable.
	streams[1].cancel()
	waitClosed(streams[1].conn, 1)
	if _, e := streams[1].conn.Write([]byte("canceled stream")); e == nil {
		t.Fatal("canceled stream accepted data")
	}
	runtimeEcho(t, streams[2].conn)
	expectedBytes += int64(len("runtime"))

	// A finishes its write side after a further multi-frame payload. Its
	// receive side must deliver the response created after request EOF.
	expectedBytes += int64(len(tail))
	a := streams[0].conn
	must(t, a.SetDeadline(time.Now().Add(8*time.Second)))
	halfClosed := make(chan transfer, 1)
	go func() {
		n, e := a.Write(tail)
		if e == nil {
			e = a.CloseWrite()
		}
		halfClosed <- transfer{n: n, err: e}
	}()
	got, readErr := io.ReadAll(io.LimitReader(a, int64(len(tailReply)+1)))
	select {
	case r := <-halfClosed:
		must(t, r.err)
		if r.n != len(tail) {
			t.Fatal("half-close truncated the outgoing tail")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("half-close writer did not join")
	}
	must(t, readErr)
	if !bytes.Equal(got, tailReply) || !requestFIN.Load() || !postFINReply.Load() {
		t.Fatal("half-close did not preserve the complete response after request EOF")
	}
	waitClosed(a, 2)
	runtimeEcho(t, streams[2].conn)
	expectedBytes += int64(len("runtime"))

	// Abandon C below the workload protocol, without an application FIN or
	// Close call. Its paired destination and every local worker must close.
	must(t, streams[2].raw.Close())
	waitClosed(streams[2].conn, 3)
	if _, e := streams[2].conn.Write([]byte("abandoned stream")); e == nil {
		t.Fatal("abandoned transport resumed application forwarding")
	}
	carrierEventually(t, func() bool { return v.server.Stats() == (workload.Stats{}) })
	for _, s := range streams {
		var receipts int
		must(t, v.carrier.policy.device.f.s.db.QueryRow("SELECT count(*) FROM session_closure_receipts WHERE session_id=?", s.conn.SessionID()).Scan(&receipts))
		if receipts != 1 {
			t.Fatal("ended stream lacks its joined-worker closure receipt")
		}
		carrierStopped(t, s.raw)
	}
	stopRuntime()
	select {
	case e := <-runtimeDone:
		must(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("runtime retained a stream or worker after all endings")
	}
	if v.connections.Load() != 3 || v.closed.Load() != 3 || v.received.Load() != expectedBytes {
		t.Fatal("stream ending replayed data or leaked destination connections")
	}
	carrierEventually(t, func() bool {
		s := v.carrier.relay.Stats()
		return s.Streams == 0 && s.Waiting == 0 && s.Endpoints == 0 && s.Watches == 0 && s.Workers == 0
	})
	t.Log("PROTO-03: three distinct ordered payloads; isolated caller cancellation, graceful half-close and abandoned carrier; all destinations and workers joined")
}
