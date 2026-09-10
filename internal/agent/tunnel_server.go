package agent

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	pb "portico.local/portico/internal/agentpb"
	"portico.local/portico/internal/client"
)

type streamBackend interface {
	ConnectReady(context.Context, string, int64, client.Input, client.Output, func() error) error
}

// Connect adds framing only. The backend still performs a fresh exact-selection
// lookup, authenticated remote open, lease renewal, revocation and final ACK.
func (s *server) Connect(stream grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	backend, ok := s.backend.(streamBackend)
	if !ok || !s.window.valid() || stream.Context().Err() != nil {
		return rejected()
	}
	if s.requests.Add(1) > maxConnections {
		s.requests.Add(-1)
		return rejected()
	}
	// A returned handler cancels gRPC's blocked Recv/Send. Keep its admission
	// slot until those workers AND the backend have actually exited. Stop joins
	// these reapers after it has joined all handlers (no later WaitGroup.Add).
	var workers sync.WaitGroup
	workers.Add(1)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		workers.Wait()
		s.requests.Add(-1)
	}()
	defer workers.Done()
	spawn := func(fn func()) {
		workers.Add(1)
		go func() { defer workers.Done(); fn() }()
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	input, received := net.Pipe()
	written, output := net.Pipe()
	defer input.Close()
	defer received.Close()
	defer written.Close()
	defer output.Close()
	ready := make(chan struct{})
	opened := make(chan *pb.TunnelFrame, 1)
	inDone, outDone, backendDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	spawn(func() {
		first, err := stream.Recv()
		if err != nil || !validFrame(first, pb.TunnelFrame_OPEN) {
			opened <- nil
			return
		}
		opened <- first
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		defer received.Close()
		inDone <- receiveInput(stream, received)
	})
	initial := time.NewTimer(operationTimeout)
	defer initial.Stop()
	var selection *pb.TunnelFrame
	select {
	case selection = <-opened:
		if selection == nil || !s.window.valid() {
			return rejected()
		}
	case <-initial.C:
		return rejected()
	case <-ctx.Done():
		return rejected()
	}
	initial.Stop()
	spawn(func() {
		defer input.Close()
		defer written.Close()
		backendDone <- backend.ConnectReady(ctx, selection.ResourceId, selection.Revision, input, written, func() error {
			if ctx.Err() != nil || !s.window.valid() || stream.Send(frame(pb.TunnelFrame_READY)) != nil {
				return ErrRejected
			}
			close(ready)
			return nil
		})
	})
	spawn(func() {
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		outDone <- sendOutput(stream, output)
	})
	opening := time.NewTimer(clientTimeout)
	defer opening.Stop()
	openDeadline := opening.C
	readyEvent := ready
	var drain *time.Timer
	var drainDeadline <-chan time.Time
	defer func() {
		if drain != nil {
			drain.Stop()
		}
	}()
	for finished := 0; finished < 3; {
		select {
		case <-readyEvent:
			readyEvent = nil
			opening.Stop()
			openDeadline = nil
		case err := <-inDone:
			if err != nil {
				return rejected()
			}
			inDone = nil
			finished++
		case err := <-outDone:
			if err != nil {
				return rejected()
			}
			outDone = nil
			finished++
		case err := <-backendDone:
			if err != nil {
				return rejected()
			}
			backendDone = nil
			finished++
			drain = time.NewTimer(operationTimeout)
			drainDeadline = drain.C
		case <-ctx.Done():
			return rejected()
		case <-openDeadline:
			return rejected()
		case <-drainDeadline:
			return rejected()
		}
	}
	if ctx.Err() != nil || !s.window.valid() {
		return rejected()
	}
	return nil
}

func receiveInput(stream grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame], output io.Writer) error {
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil || !validFrame(r, pb.TunnelFrame_DATA) {
			return ErrRejected
		}
		if n, err := output.Write(r.Data); err != nil || n != len(r.Data) {
			return ErrRejected
		}
	}
}

func sendOutput(stream grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame], input io.Reader) error {
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
			return stream.Send(frame(pb.TunnelFrame_FIN))
		}
		if err != nil {
			return ErrRejected
		}
	}
}
