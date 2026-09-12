package client

import (
	"context"
	"io"
	"sync"
	"time"

	"portico.local/portico/internal/workload"
)

type Input interface {
	io.ReadCloser
	SetReadDeadline(time.Time) error
}
type Output interface {
	io.WriteCloser
	SetWriteDeadline(time.Time) error
}

// Connect owns both local endpoints and joins their copy workers. They must be
// pollable: Close/deadlines interrupt blocked operations. There is no listener,
// proxy target field or cached permit. Configuration selects native clock health.
func (c *Configuration) Connect(ctx context.Context, id string, revision int64, input Input, output Output) error {
	return c.connect(ctx, id, revision, input, output, nil)
}

// ConnectReady reports successful remote authorization/open before consuming
// application input. A failed notification closes the already opened stream;
// it never supplies or substitutes a permit. Endpoint ownership matches Connect.
func (c *Configuration) ConnectReady(ctx context.Context, id string, revision int64, input Input, output Output, ready func() error) error {
	if ready == nil {
		return ErrConfiguration
	}
	return c.connect(ctx, id, revision, input, output, ready)
}

func (c *Configuration) connect(ctx context.Context, id string, revision int64, input Input, output Output, ready func() error) error {
	if input == nil || output == nil {
		return ErrConfiguration
	}
	defer input.Close()
	defer output.Close()
	if input.SetReadDeadline(time.Time{}) != nil || output.SetWriteDeadline(time.Time{}) != nil {
		return ErrConfiguration
	}
	connection, err := c.open(ctx, id, revision)
	if err != nil {
		return err
	}
	defer connection.close()
	if ready != nil && ready() != nil {
		return ErrConnection
	}
	return forward(ctx, connection.stream, input, output, c.workload.OperationTimeout)
}

func forward(ctx context.Context, remote *workload.Conn, input Input, output Output, drain time.Duration) error {
	var once sync.Once
	stop := func() { once.Do(func() { _ = remote.Close(); _ = input.Close(); _ = output.Close() }) }
	defer stop()
	type result struct {
		input bool
		err   error
	}
	results := make(chan result, 2)
	go func() {
		_, err := io.CopyBuffer(struct{ io.Writer }{remote}, struct{ io.Reader }{input}, make([]byte, 32768))
		if err == nil {
			err = remote.CloseWrite()
		}
		results <- result{input: true, err: err}
	}()
	go func() {
		_, err := io.CopyBuffer(struct{ io.Writer }{output}, struct{ io.Reader }{remote}, make([]byte, 32768))
		results <- result{err: err}
	}()
	failed, finished := false, 0
	outputFinished := false
	terminal, canceled := remote.Done(), ctx.Done()
	for finished < 2 {
		select {
		case r := <-results:
			finished++
			if !r.input {
				outputFinished = true
			}
			if r.err != nil {
				failed = true
				stop()
			}
			if !r.input && r.err == nil {
				_ = output.Close()
			}
		case <-canceled:
			failed = true
			canceled = nil
			stop()
		case <-terminal:
			terminal = nil
			if remote.ReadFinished() {
				// FIN means all incoming DATA has already been read into the
				// application copy path. Drain at most that final bounded chunk,
				// with a deadline; do not turn a graceful carrier end into data
				// loss. No new remote payload can be read after this FIN.
				_ = input.Close()
				if !outputFinished && output.SetWriteDeadline(time.Now().Add(drain)) != nil {
					failed = true
					stop()
				}
			} else {
				failed = true
				stop()
			}
		}
	}
	if failed || ctx.Err() != nil {
		return ErrConnection
	}
	ack, cancel := context.WithTimeout(ctx, drain)
	defer cancel()
	if remote.WaitWriteAcknowledged(ack) != nil {
		return ErrConnection
	}
	return nil
}
