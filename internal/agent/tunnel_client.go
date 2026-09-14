package agent

import (
	"context"
	"io"
	"time"

	"google.golang.org/grpc"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
)

// Connect owns the pollable application endpoints. It reads no application
// input before READY, preserves output half-close, and requires both input FIN
// and final successful RPC status. Receiving output EOF alone is not success.
func Connect(ctx context.Context, path, id string, revision int64, input client.Input, output client.Output) error {
	if input == nil || output == nil {
		return ErrRejected
	}
	defer input.Close()
	defer output.Close()
	open := frame(pb.TunnelFrame_OPEN)
	open.ResourceId, open.Revision = id, revision
	if ctx == nil || ctx.Err() != nil || !validFrame(open, pb.TunnelFrame_OPEN) || input.SetReadDeadline(time.Time{}) != nil || output.SetWriteDeadline(time.Time{}) != nil {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, unlockLifetime)
	defer cancel()
	c, err := newClient(path)
	if err != nil {
		return ErrRejected
	}
	defer c.Close()
	opening := time.AfterFunc(clientTimeout, cancel)
	defer opening.Stop()
	stream, err := pb.NewAgentClient(c).Connect(ctx)
	if err != nil {
		return ErrRejected
	}
	ready := make(chan error, 1)
	go func() {
		if stream.Send(open) != nil {
			ready <- ErrRejected
			return
		}
		r, err := stream.Recv()
		if err != nil || !validFrame(r, pb.TunnelFrame_READY) {
			ready <- ErrRejected
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			return ErrRejected
		}
	case <-ctx.Done():
		cancel()
		_ = c.Close()
		<-ready
		return ErrRejected
	}
	opening.Stop()
	type result struct {
		output bool
		err    error
	}
	results := make(chan result, 2)
	go func() { results <- result{err: sendInput(stream, input)} }()
	go func() { results <- result{output: true, err: receiveOutput(stream, output)} }()
	failed := false
	canceled := ctx.Done()
	var drain *time.Timer
	var drainDeadline <-chan time.Time
	defer func() {
		if drain != nil {
			drain.Stop()
		}
	}()
	stop := func() {
		cancel()
		_ = c.Close()
		_ = input.Close()
		_ = output.Close()
	}
	for finished := 0; finished < 2; {
		select {
		case r := <-results:
			finished++
			if r.err != nil {
				failed = true
				stop()
			} else if r.output {
				drain = time.NewTimer(operationTimeout)
				drainDeadline = drain.C
			}
		case <-canceled:
			canceled = nil
			failed = true
			stop()
		case <-drainDeadline:
			drainDeadline = nil
			failed = true
			stop()
		}
	}
	if failed || ctx.Err() != nil {
		return ErrRejected
	}
	return nil
}

func sendInput(stream grpc.BidiStreamingClient[pb.TunnelFrame, pb.TunnelFrame], input io.Reader) error {
	for {
		data := make([]byte, maxChunk)
		n, err := input.Read(data)
		if n > 0 {
			r := frame(pb.TunnelFrame_DATA)
			r.Data = data[:n]
			if stream.Send(r) != nil {
				return ErrRejected
			}
		}
		if err == io.EOF {
			return stream.CloseSend()
		}
		if err != nil {
			return ErrRejected
		}
	}
}

func receiveOutput(stream grpc.BidiStreamingClient[pb.TunnelFrame, pb.TunnelFrame], output client.Output) error {
	finished := false
	for {
		r, err := stream.Recv()
		if err == io.EOF && finished {
			return nil
		}
		if err != nil || finished {
			return ErrRejected
		}
		if validFrame(r, pb.TunnelFrame_FIN) {
			if output.Close() != nil {
				return ErrRejected
			}
			finished = true
		} else if validFrame(r, pb.TunnelFrame_DATA) {
			// gRPC final status is read through Recv; it cannot interrupt a
			// caller blocked writing an earlier DATA frame. Bound each local
			// delivery so agent shutdown/revocation cannot strand that worker.
			if output.SetWriteDeadline(time.Now().Add(operationTimeout)) != nil {
				return ErrRejected
			}
			if n, err := output.Write(r.Data); err != nil || n != len(r.Data) {
				return ErrRejected
			}
		} else {
			return ErrRejected
		}
	}
}
