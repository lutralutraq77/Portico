package workload

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func payloadPair(t *testing.T) (*payloadConn, *payloadConn) {
	t.Helper()
	a, b := net.Pipe()
	left := newPayload(context.Background(), a, a)
	right := newPayload(context.Background(), b, b)
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		for _, c := range []*payloadConn{left, right} {
			select {
			case <-c.Done():
			case <-time.After(time.Second):
				t.Error("payload workers did not join")
			}
		}
	})
	return left, right
}

// A local application may still be delivering the last already-read chunk
// when the peer completes FIN/ACK and closes its carrier. A subsequent Read
// must preserve the validated EOF without exposing any bytes after closure.
func TestClientPreservesConsumedFINAfterCarrierCloses(t *testing.T) {
	for _, fin := range []bool{false, true} {
		t.Run(map[bool]string{false: "abandon", true: "consumed_fin"}[fin], func(t *testing.T) {
			left, right := payloadPair(t)
			if fin {
				sent := make(chan error, 1)
				go func() {
					_, e := right.Write([]byte("tail"))
					if e == nil {
						e = right.CloseWrite()
					}
					sent <- e
				}()
				var tail [4]byte
				if _, e := io.ReadFull(left, tail[:]); e != nil || string(tail[:]) != "tail" {
					t.Fatal("missing final data")
				}
				var empty [1]byte
				if n, e := left.Read(empty[:]); n != 0 || e != io.EOF {
					t.Fatal("FIN did not complete framed input")
				}
				if e := <-sent; e != nil {
					t.Fatal(e)
				}
			}
			_ = right.Close()
			select {
			case <-left.Done():
			case <-time.After(time.Second):
				t.Fatal("carrier did not terminate")
			}
			clock := &clock{health: func() (time.Duration, error) { return time.Millisecond, nil }, readBoot: func() (time.Duration, error) { return time.Hour, nil }, readWall: time.Now}
			root, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &Conn{owner: &Client{clock: clock}, ctx: root, cancel: cancel, raw: left.raw, payload: left, closed: true}
			var b [1]byte
			n, e := c.Read(b[:])
			want := ErrDenied
			if fin {
				want = io.EOF
			}
			if n != 0 || e != want {
				t.Fatalf("closed read: bytes=%d err=%v want=%v", n, e, want)
			}
			if n, e := c.Write([]byte("after closure")); n != 0 || e != ErrDenied {
				t.Fatal("closed connection revived output authority")
			}
		})
	}
}

func TestPayloadHalfCloseWaitsForRemoteConsumption(t *testing.T) {
	left, right := payloadPair(t)
	data := bytes.Repeat([]byte("bounded payload"), 8192)
	sent := make(chan error, 1)
	go func() {
		_, e := left.Write(data)
		if e == nil {
			e = left.CloseWrite()
		}
		sent <- e
	}()
	got, e := io.ReadAll(right)
	if e != nil || !bytes.Equal(got, data) {
		t.Fatal("payload truncated", e)
	}
	if e := <-sent; e != nil {
		t.Fatal(e)
	}
	if _, e := left.Write([]byte("after FIN")); e == nil {
		t.Fatal("write after FIN accepted")
	}
	// The reverse direction remains usable after the first FIN.
	reply := []byte("complete reply")
	go func() {
		_, e := right.Write(reply)
		if e == nil {
			e = right.CloseWrite()
		}
		sent <- e
	}()
	got, e = io.ReadAll(left)
	if e != nil || !bytes.Equal(got, reply) {
		t.Fatal("half-close truncated reverse data", e)
	}
	if e := <-sent; e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if left.waitAcknowledged(ctx) != nil || right.waitAcknowledged(ctx) != nil {
		t.Fatal("FIN acknowledgments did not complete")
	}
}

func TestPayloadUnconsumedDataCannotBeAcknowledged(t *testing.T) {
	left, right := payloadPair(t)
	sent := make(chan error, 1)
	go func() {
		_, e := left.Write([]byte("unconsumed"))
		if e == nil {
			e = left.CloseWrite()
		}
		sent <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if left.waitAcknowledged(ctx) == nil {
		t.Fatal("unconsumed application bytes were acknowledged")
	}
	_ = right.Close()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("blocked writer survived closure")
	}
}

func TestPayloadSimultaneousFINDoesNotDeadlock(t *testing.T) {
	left, right := payloadPair(t)
	closed := make(chan error, 2)
	go func() { closed <- left.CloseWrite() }()
	go func() { closed <- right.CloseWrite() }()
	for i := 0; i < 2; i++ {
		select {
		case e := <-closed:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("simultaneous FIN deadlocked")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if left.waitAcknowledged(ctx) != nil || right.waitAcknowledged(ctx) != nil {
		t.Fatal("simultaneous ACK deadlocked")
	}
}

func TestPayloadRejectsMalformedControlFrames(t *testing.T) {
	for _, name := range []string{"zero_data", "oversize", "unknown", "unexpected_ack", "fin_payload", "truncated_header", "truncated_data"} {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			c := newPayload(context.Background(), a, a)
			defer c.Close()
			defer b.Close()
			var header [5]byte
			header[0] = payloadData
			switch name {
			case "oversize":
				binary.BigEndian.PutUint32(header[1:], chunkSize+1)
			case "unknown":
				header[0] = 255
			case "unexpected_ack":
				header[0] = payloadACK
			case "fin_payload":
				header[0] = payloadFIN
				header[4] = 1
			case "truncated_data":
				header[4] = 1
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if name == "truncated_header" {
					_, _ = b.Write(header[:2])
				} else {
					_, _ = b.Write(header[:])
				}
				_ = b.Close()
			}()
			select {
			case <-c.Done():
			case <-time.After(time.Second):
				t.Fatal("invalid frame did not terminate workers")
			}
			<-done
			if _, e := c.Read(make([]byte, 1)); e == nil || e == io.EOF {
				t.Fatal("malformed input became clean EOF")
			}
		})
	}
}
