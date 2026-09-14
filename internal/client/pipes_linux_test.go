package client

import (
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rawPipes(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var fds [2]int
	if e := unix.Pipe2(fds[:], unix.O_CLOEXEC); e != nil {
		t.Fatal(e)
	}
	r, w := os.NewFile(uintptr(fds[0]), "input"), os.NewFile(uintptr(fds[1]), "output")
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func pipeFlags(t *testing.T, f *os.File) int {
	t.Helper()
	raw, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var flags int
	var inner error
	if e = raw.Control(func(fd uintptr) { flags, inner = unix.FcntlInt(fd, unix.F_GETFL, 0) }); e != nil || inner != nil {
		t.Fatal("could not inspect pipe flags")
	}
	return flags
}

func TestApplicationPipesOwnCancellationWithoutChangingCallerFlags(t *testing.T) {
	in, source := rawPipes(t)
	sink, out := rawPipes(t)
	inFlags, outFlags := pipeFlags(t, in), pipeFlags(t, out)
	input, output, e := OpenPipes(in, out)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })
	if pipeFlags(t, in) != inFlags || pipeFlags(t, out) != outFlags {
		t.Fatal("adapter changed shared pipe flags")
	}
	if e = in.Close(); e != nil {
		t.Fatal(e)
	}
	if e = out.Close(); e != nil {
		t.Fatal(e)
	}
	readDone := make(chan error, 1)
	go func() { var b [1]byte; _, e := input.Read(b[:]); readDone <- e }()
	writeDone := make(chan error, 1)
	go func() { _, e := output.Write(make([]byte, 1024*1024)); writeDone <- e }()
	select {
	case <-writeDone:
		t.Fatal("unread application pipe did not backpressure")
	case <-time.After(20 * time.Millisecond):
	}
	_ = input.Close()
	_ = output.Close()
	for _, done := range []<-chan error{readDone, writeDone} {
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("closed blocked pipe unexpectedly succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("pipe close failed to join blocked I/O")
		}
	}
	_ = source.Close()
	if _, e := io.Copy(io.Discard, sink); e != nil {
		t.Fatal(e)
	}
}

func TestApplicationPipesRejectWrongDirectionAndRegularFiles(t *testing.T) {
	r, w := rawPipes(t)
	for _, pair := range [][2]*os.File{{nil, w}, {w, w}, {r, r}, {r, nil}} {
		if a, b, e := OpenPipes(pair[0], pair[1]); e == nil || a != nil || b != nil {
			t.Fatal("invalid pipe directions accepted")
		}
	}
	f, e := os.CreateTemp(t.TempDir(), "regular")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if a, b, e := OpenPipes(f, w); e == nil || a != nil || b != nil {
		t.Fatal("regular file accepted as cancellable application pipe")
	}
}
