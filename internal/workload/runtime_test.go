package workload

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestRequestStartWindowCannotExtendLease(t *testing.T) {
	w := time.Now().UTC()
	start := sample{time.Hour, w, 10 * time.Millisecond}
	for _, name := range []string{"valid", "delayed", "expired_wall", "future_issued", "old_issued", "oversize", "backward", "uncertain", "overflow"} {
		t.Run(name, func(t *testing.T) {
			s := start
			n := sample{s.boot + time.Second, w.Add(time.Second), 10 * time.Millisecond}
			issued, end := w, w.Add(2*time.Second)
			switch name {
			case "delayed":
				n.boot = s.boot + 3*time.Second
			case "expired_wall":
				n.wall = end
			case "future_issued":
				issued = n.wall.Add(time.Second)
				end = issued.Add(time.Second)
			case "old_issued":
				issued = w.Add(-time.Second)
			case "oversize":
				end = w.Add(16 * time.Second)
			case "backward":
				n.boot = s.boot - time.Second
			case "uncertain":
				n.uncertainty = 2 * time.Second
			case "overflow":
				s.boot = math.MaxInt64 - time.Second
				n.boot = s.boot
			}
			deadline, e := window(s, n, issued, end, 15*time.Second)
			if name == "valid" {
				if e != nil || deadline != start.boot+2*time.Second-20*time.Millisecond {
					t.Fatal("lease anchored to response receipt")
				}
			} else if e == nil {
				t.Fatal("unsafe lease accepted")
			}
		})
	}
}

func TestClockHealthAndRollbackLatch(t *testing.T) {
	for _, name := range []string{"boot_back", "wall_back", "wall_forward", "health", "uncertainty", "native_error", "slow_sample"} {
		t.Run(name, func(t *testing.T) {
			boot := time.Hour
			wall := time.Now().UTC()
			healthError := error(nil)
			nativeError := error(nil)
			uncertainty := time.Millisecond
			step := time.Duration(0)
			c := &clock{health: func() (time.Duration, error) { return uncertainty, healthError }, readBoot: func() (time.Duration, error) { boot += step; return boot, nativeError }, readWall: func() time.Time { return wall }}
			if _, e := c.now(); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "boot_back":
				boot -= time.Second
			case "wall_back":
				wall = wall.Add(-time.Nanosecond)
			case "wall_forward":
				wall = wall.Add(time.Minute)
			case "health":
				healthError = errors.New("no current health estimate")
			case "uncertainty":
				uncertainty = 31 * time.Second
			case "native_error":
				nativeError = errors.New("native read failed")
			case "slow_sample":
				step = time.Second
			}
			if _, e := c.now(); e == nil {
				t.Fatal("unhealthy clock allowed authority")
			}
			boot = time.Hour
			wall = time.Now().UTC()
			healthError = nil
			nativeError = nil
			uncertainty = 0
			step = 0
			if _, e := c.now(); e == nil {
				t.Fatal("clock latch revived authority")
			}
		})
	}
}

type blockedClose struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

// A terminal carrier can close while the framing reader is blocked delivering
// already-received DATA to an application that is not reading.
type terminalCarrier struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *terminalCarrier) Done() <-chan struct{} { return c.done }
func (c *terminalCarrier) Close() error {
	c.once.Do(func() { _ = c.Conn.Close(); close(c.done) })
	return nil
}

func TestCarrierTerminationStopsBackpressuredPayload(t *testing.T) {
	for _, serverSide := range []bool{false, true} {
		name := "client"
		if serverSide {
			name = "server"
		}
		t.Run(name, func(t *testing.T) {
			root, cancel := context.WithCancel(context.Background())
			a, b := net.Pipe()
			raw := &terminalCarrier{Conn: a, done: make(chan struct{})}
			receiver := newPayload(root, raw, raw)
			producer := newPayload(context.Background(), b, b)
			t.Cleanup(func() {
				cancel()
				_ = receiver.Close()
				_ = producer.Close()
				for _, done := range []<-chan struct{}{receiver.Done(), producer.Done()} {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("framing cleanup did not join")
					}
				}
			})
			c := newClock(func() (time.Duration, error) { return time.Millisecond, nil })
			now, e := c.now()
			if e != nil {
				t.Fatal(e)
			}
			var work *sync.WaitGroup
			var destinationPeer net.Conn
			if serverSide {
				destination, peer := net.Pipe()
				destinationPeer = peer
				t.Cleanup(func() { _ = destination.Close(); _ = peer.Close() })
				x := &session{server: &Server{clock: c}, raw: raw, destinationConn: destination, ctx: root, cancel: cancel, active: true, lease: now.boot + time.Minute, idle: now.boot + time.Minute, absolute: now.wall.Add(time.Minute)}
				work = &x.work
				work.Add(1)
				go x.supervise()
			} else {
				x := &Conn{owner: &Client{clock: c}, raw: raw, ctx: root, cancel: cancel, lease: now.boot + time.Minute, absoluteBoot: now.boot + time.Minute, idle: now.boot + time.Minute, absolute: now.wall.Add(time.Minute)}
				work = &x.work
				work.Add(1)
				go x.supervise()
			}
			joined := make(chan struct{})
			go func() { work.Wait(); close(joined) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("supervisor cleanup did not join")
				}
			})
			// A completed write means the framing reader consumed this entire
			// frame from net.Pipe. Nobody reads receiver's application pipe.
			_ = b.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e := producer.Write([]byte("received but unconsumed DATA")); e != nil {
				t.Fatal(e)
			}
			select {
			case <-receiver.Done():
				t.Fatal("receiver ended before the carrier")
			default:
			}
			_ = raw.Close()
			for _, done := range []<-chan struct{}{joined, receiver.Done()} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("terminal carrier retained supervisor or backpressured framing despite valid future lease")
				}
			}
			if destinationPeer != nil {
				_ = destinationPeer.SetReadDeadline(time.Now().Add(time.Second))
				var data [1]byte
				if _, e := destinationPeer.Read(data[:]); e != io.EOF {
					t.Fatalf("terminal carrier retained destination handle: %v", e)
				}
			}
		})
	}
}

func (c *blockedClose) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}
func TestConcurrentStopWaitsForActualHandleClosure(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	raw := &blockedClose{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := &session{raw: raw, ctx: ctx, cancel: cancel}
	first := make(chan struct{})
	second := make(chan struct{})
	go func() { x.stop(); close(first) }()
	<-raw.entered
	go func() { x.stop(); close(second) }()
	select {
	case <-second:
		t.Fatal("second stop preceded actual handle closure")
	case <-time.After(20 * time.Millisecond):
	}
	close(raw.release)
	for _, done := range []<-chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("stop did not join close")
		}
	}
}

func TestWorkloadFramingRejectsMalformedRequests(t *testing.T) {
	for _, body := range []string{`{"Version":1,"Version":2}`, `{"Version":1,"Address":"192.0.2.10"}`, `{} {}`, `null`, `[]`} {
		var data bytes.Buffer
		_ = binary.Write(&data, binary.BigEndian, uint32(len(body)))
		data.WriteString(body)
		if readMessage(&data, &openRequest{}) == nil {
			t.Fatal("ambiguous or destination-bearing request accepted")
		}
	}
	for _, size := range []uint32{0, maxMessage + 1, math.MaxUint32} {
		var data bytes.Buffer
		_ = binary.Write(&data, binary.BigEndian, size)
		if readMessage(&data, &openRequest{}) == nil {
			t.Fatal("unbounded header accepted")
		}
	}
	if readMessage(bytes.NewReader([]byte{0, 0}), &openRequest{}) == nil {
		t.Fatal("truncated prefix accepted")
	}
}
func FuzzWorkloadOpen(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		var request openRequest
		if readMessage(bytes.NewReader(data), &request) != nil {
			return
		}
		var encoded bytes.Buffer
		if writeMessage(&encoded, request) != nil {
			t.Fatal("decoded bounded message cannot re-encode")
		}
		var result openRequest
		if readMessage(&encoded, &result) != nil || !reflect.DeepEqual(request, result) {
			t.Fatal("round-trip changed request")
		}
	})
}

func TestForwardingStopsBlockedWriteAtLease(t *testing.T) {
	// Deadline enforcement is also exercised through real destination TCP in
	// the isolated-VM integration test. This fixture forces blocked Go writes.
	a, b := net.Pipe()
	defer b.Close()
	dst, reader := net.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newClock(func() (time.Duration, error) { return time.Millisecond, nil })
	now, e := c.now()
	if e != nil {
		t.Fatal(e)
	}
	s := &Server{clock: c, config: ServerConfig{IdleTimeout: time.Second, OperationTimeout: time.Second}}
	x := &session{server: s, raw: a, destinationConn: dst, ctx: ctx, cancel: cancel, active: true, lease: now.boot + 150*time.Millisecond, idle: now.boot + time.Second, absolute: now.wall.Add(time.Hour)}
	x.work.Add(1)
	go x.supervise()
	finished := make(chan error, 1)
	go func() { finished <- x.copy(dst, a) }()
	wrote := make(chan struct{})
	go func() { defer close(wrote); _, _ = io.Copy(b, bytes.NewReader(make([]byte, chunkSize*2))) }()
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("blocked stream survived expired lease")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expiry did not unblock forwarding")
	}
	x.stop()
	x.work.Wait()
	select {
	case <-wrote:
	case <-time.After(time.Second):
		t.Fatal("source writer did not join")
	}
}
