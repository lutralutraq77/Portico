package workload

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const (
	payloadData byte = 1
	payloadFIN  byte = 2
	payloadACK  byte = 3
)

// payloadConn frames the application bytes inside authenticated inner TLS.
// A FIN ACK confirms consumption of every preceding frame. The connector waits
// for that ACK before closing the carrier; a local TLS Write alone cannot prove
// that asynchronously transported final bytes reached the remote reader.
type payloadConn struct {
	net.Conn
	raw                                   net.Conn
	ctx                                   context.Context
	cancel                                context.CancelFunc
	reader                                *io.PipeReader
	writer                                *io.PipeWriter
	writeMu                               sync.Mutex
	mu                                    sync.Mutex
	writeClosed, readClosed, acknowledged bool
	ack, done                             chan struct{}
	ackNeeded                             chan struct{}
	once                                  sync.Once
}

func newPayload(parent context.Context, inner, raw net.Conn) *payloadConn {
	ctx, cancel := context.WithCancel(parent)
	r, w := io.Pipe()
	c := &payloadConn{Conn: inner, raw: raw, ctx: ctx, cancel: cancel, reader: r, writer: w, ack: make(chan struct{}), done: make(chan struct{}), ackNeeded: make(chan struct{}, 1)}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); defer c.Close(); c.receive() }()
	go func() {
		defer workers.Done()
		select {
		case <-c.ctx.Done():
			return
		case <-c.ackNeeded:
			c.writeMu.Lock()
			e := c.frame(payloadACK, nil)
			c.writeMu.Unlock()
			if e != nil {
				_ = c.Close()
			}
		}
	}()
	go func() { workers.Wait(); stop(); close(c.done) }()
	return c
}

func (c *payloadConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		finished := c.readClosed
		c.mu.Unlock()
		if finished {
			_ = c.writer.Close()
		} else {
			_ = c.writer.CloseWithError(ErrDenied)
		}
		_ = c.raw.Close()
	})
	return nil
}
func (c *payloadConn) Done() <-chan struct{}      { return c.done }
func (c *payloadConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *payloadConn) readFinished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readClosed
}

// frame requires writeMu, including for ACKs sent by the receive worker.
func (c *payloadConn) frame(kind byte, data []byte) error {
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, e := c.Conn.Write(part)
			if e != nil || n <= 0 {
				return ErrDenied
			}
			part = part[n:]
		}
	}
	return nil
}
func (c *payloadConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	closed := c.writeClosed
	c.mu.Unlock()
	if closed || c.ctx.Err() != nil {
		return 0, ErrDenied
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		if e := c.frame(payloadData, p[:n]); e != nil {
			_ = c.Close()
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *payloadConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	closed := c.writeClosed
	c.writeClosed = true
	c.mu.Unlock()
	if closed {
		return nil
	}
	if c.ctx.Err() != nil {
		return ErrDenied
	}
	if e := c.frame(payloadFIN, nil); e != nil {
		_ = c.Close()
		return e
	}
	return nil
}
func (c *payloadConn) waitAcknowledged(ctx context.Context) error {
	// A valid ACK remains evidence of consumption after the carrier closes.
	select {
	case <-c.ack:
		return nil
	default:
	}
	select {
	case <-c.ack:
		return nil
	case <-ctx.Done():
		return ErrDenied
	case <-c.ctx.Done():
		select {
		case <-c.ack:
			return nil
		default:
			return ErrDenied
		}
	}
}
func (c *payloadConn) receive() {
	buffer := make([]byte, chunkSize)
	for {
		var header [5]byte
		if _, e := io.ReadFull(c.Conn, header[:]); e != nil {
			return
		}
		n := binary.BigEndian.Uint32(header[1:])
		c.mu.Lock()
		finished := c.readClosed
		c.mu.Unlock()
		switch header[0] {
		case payloadData:
			if finished || n == 0 || n > chunkSize {
				return
			}
			if _, e := io.ReadFull(c.Conn, buffer[:n]); e != nil {
				return
			}
			if _, e := c.writer.Write(buffer[:n]); e != nil {
				return
			}
		case payloadFIN:
			if finished || n != 0 {
				return
			}
			c.mu.Lock()
			c.readClosed = true
			c.mu.Unlock()
			_ = c.writer.Close()
			c.ackNeeded <- struct{}{}
		case payloadACK:
			c.mu.Lock()
			valid := n == 0 && c.writeClosed && !c.acknowledged
			if valid {
				c.acknowledged = true
				close(c.ack)
			}
			c.mu.Unlock()
			if !valid {
				return
			}
		default:
			return
		}
	}
}
