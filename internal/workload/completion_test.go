package workload

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestClientCompletionCannotOvertakeFinalRead(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	left := newClientPayload(ctx, a, a)
	right, forwarded := newServerPayload(ctx, b, b)
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	resume := func() { unblock.Do(func() { close(release) }) }
	wall := time.Now()
	calls := 0
	clock := &clock{
		readBoot: func() (time.Duration, error) { return time.Hour, nil },
		readWall: func() time.Time { return wall },
		health: func() (time.Duration, error) {
			calls++
			// CloseWrite and the pre-read check precede this post-read check.
			// Pause after the final DATA leaves the pipe, while Read still
			// owns the bytes and has not returned them to its caller.
			if calls == 3 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return time.Millisecond, nil
		},
	}
	root, stop := context.WithCancel(ctx)
	c := &Conn{owner: &Client{clock: clock, config: ClientConfig{IdleTimeout: time.Minute}}, ctx: root, cancel: stop, raw: a, payload: left, lease: 2 * time.Hour, absoluteBoot: 2 * time.Hour, idle: 2 * time.Hour, absolute: wall.Add(time.Hour), done: left.done}
	joined := make(chan struct{})
	go func() { defer close(joined); <-left.Done(); _ = c.Close() }()
	t.Cleanup(func() {
		resume()
		_ = c.Close()
		_ = right.Close()
		for _, done := range []<-chan struct{}{left.Done(), right.Done(), joined} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("completion test retained a worker")
			}
		}
	})
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		_, err := right.Write([]byte("tail"))
		if err == nil {
			err = right.CloseWrite()
		}
		if err == nil {
			forwarded()
			err = right.waitAcknowledged(ctx)
		}
		_ = right.Close()
		served <- err
	}()
	type readResult struct {
		n    int
		err  error
		data [4]byte
	}
	read := make(chan readResult, 1)
	go func() { var result readResult; result.n, result.err = c.Read(result.data[:]); read <- result }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("final read did not reach its activity check")
	}
	select {
	case err := <-served:
		t.Fatalf("connector closed before the final read returned: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	resume()
	result := <-read
	if result.n != 4 || result.err != nil || string(result.data[:]) != "tail" {
		t.Fatalf("final read lost authorized data: n=%d err=%v", result.n, result.err)
	}
	var empty [1]byte
	if n, err := c.Read(empty[:]); n != 0 || err != io.EOF {
		t.Fatal("final read did not retain FIN")
	}
	if err := c.WaitFinished(ctx); err != nil {
		t.Fatal("consumed stream did not complete", err)
	}
	if err := <-served; err != nil {
		t.Fatal("connector completion failed", err)
	}
}

func TestClientCompletionDoesNotAcknowledgeCanceledForwarding(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	left := newClientPayload(ctx, a, a)
	right, forwarded := newServerPayload(ctx, b, b)
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		for _, stream := range []*payloadConn{left, right} {
			select {
			case <-stream.Done():
			case <-time.After(time.Second):
				t.Error("canceled forwarding retained a worker")
			}
		}
	})
	if left.CloseWrite() != nil || right.CloseWrite() != nil {
		t.Fatal("fixture FIN exchange failed")
	}
	forwarded()
	if left.waitAcknowledged(ctx) != nil {
		t.Fatal("connector did not acknowledge successful destination forwarding")
	}
	c := &Conn{payload: left, done: left.done}
	canceled, abort := context.WithCancel(ctx)
	abort()
	if c.WaitFinished(canceled) == nil {
		t.Fatal("canceled local forwarding acquired completion")
	}
	wait, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if right.waitAcknowledged(wait) == nil {
		t.Fatal("connector received an ACK before successful local forwarding")
	}
	_ = left.Close()
	if right.waitAcknowledged(ctx) == nil {
		t.Fatal("abandoned local forwarding became successful completion")
	}
}
