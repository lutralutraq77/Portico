package adminbridge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Launch identifies a locally installed, verified native shell and its private
// state directory. The application installer/owner must protect these paths.
// This API accepts no extra browser switches or caller-supplied environment.
type Launch struct{ Executable, EntryPoint, StateDirectory string }

// Run owns the child and all pipe workers. The native Client retains the signer
// and exposes only bounded fixed-origin HTTP through this child's private pipes.
func Run(parent context.Context, client *Client, spec Launch) error {
	if parent == nil || parent.Err() != nil || client == nil {
		return ErrRejected
	}
	for _, path := range []string{spec.Executable, spec.EntryPoint, spec.StateDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
			return fmt.Errorf("%w: invalid launch path", ErrRejected)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer client.Close()
	stopClient := context.AfterFunc(client.context, cancel)
	defer stopClient()
	cmd := exec.CommandContext(ctx, spec.Executable, spec.EntryPoint)
	cmd.WaitDelay = 5 * time.Second
	// Own all child descriptors ourselves. exec.Wait must not close an active
	// protocol reader, and inherited Chromium stderr must not hold a copy worker.
	stderr, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return ErrRejected
	}
	defer stderr.Close()
	cmd.Stderr = stderr
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		name = strings.ToUpper(name)
		if strings.HasPrefix(name, "ELECTRON_") || strings.HasPrefix(name, "NODE_") || strings.HasPrefix(name, "PORTICO_NATIVE_") || name == "SSLKEYLOGFILE" {
			continue
		}
		cmd.Env = append(cmd.Env, value)
	}
	cmd.Env = append(cmd.Env, "PORTICO_NATIVE_STATE="+spec.StateDirectory)
	// Prevent console attachment; the application communicates only by pipe.
	cmd.Env = append(cmd.Env, "ELECTRON_NO_ATTACH_CONSOLE=1")
	in, childOutput, err := os.Pipe()
	if err != nil {
		return ErrRejected
	}
	defer in.Close()
	defer childOutput.Close()
	childInput, out, err := os.Pipe()
	if err != nil {
		return ErrRejected
	}
	defer childInput.Close()
	defer out.Close()
	cmd.Stdin, cmd.Stdout = childInput, childOutput
	if cmd.Start() != nil {
		_ = in.Close()
		_ = out.Close()
		return fmt.Errorf("%w: child start", ErrRejected)
	}
	_ = childInput.Close()
	_ = childOutput.Close()
	served := make(chan error, 1)
	var input io.ReadCloser = in
	if runtime.GOOS == "windows" {
		input = &shellOutput{Reader: bufio.NewReader(in), Closer: in}
	}
	go func() { served <- Serve(ctx, client, input, out, spec.StateDirectory) }()
	joined := make(chan error, 1)
	go func() { joined <- cmd.Wait() }()
	var serveErr, exitErr error
	var grace <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	startGrace := func() {
		if timer == nil {
			timer = time.NewTimer(5 * time.Second)
			grace = timer.C
		}
	}
	stop := func() { cancel(); _ = in.Close(); _ = out.Close() }
	done := ctx.Done()
	for served != nil || joined != nil {
		select {
		case serveErr = <-served:
			served = nil
			startGrace()
			if serveErr != nil {
				stop()
			}
		case exitErr = <-joined:
			joined = nil
			startGrace()
			if exitErr != nil {
				stop()
			}
		case <-done:
			stop()
			done = nil
		case <-grace:
			stop()
			grace = nil
		}
	}
	if serveErr != nil {
		return fmt.Errorf("%w: child channel: %w", ErrRejected, serveErr)
	}
	if exitErr != nil || ctx.Err() != nil {
		return fmt.Errorf("%w: child exit", ErrRejected)
	}
	return nil
}

// The pinned Windows Electron runtime emits one CRLF before application bytes,
// including with console attachment disabled. Accept exactly that optional
// startup preamble once. No later whitespace or malformed frame is skipped.
// Close still interrupts the underlying pipe if the child sends no prefix.
type shellOutput struct {
	*bufio.Reader
	io.Closer
	started bool
}

func (r *shellOutput) Read(p []byte) (int, error) {
	if !r.started {
		r.started = true
		prefix, err := r.Peek(2)
		if err != nil {
			return 0, err
		}
		if string(prefix) == "\r\n" {
			_, _ = r.Discard(2)
		}
	}
	return r.Reader.Read(p)
}
