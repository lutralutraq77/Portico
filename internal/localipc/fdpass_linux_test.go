//go:build linux

package localipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func descriptorPair(t *testing.T, kind int) (*os.File, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
	must(t, err)
	sender := os.NewFile(uintptr(fds[0]), "descriptor-sender")
	receiverFile := os.NewFile(uintptr(fds[1]), "descriptor-receiver")
	receiver, err := net.FileConn(receiverFile)
	must(t, receiverFile.Close())
	must(t, err)
	t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })
	must(t, receiver.SetDeadline(time.Now().Add(5*time.Second)))
	return sender, receiver.(*net.UnixConn)
}

func receiveDescriptor(t *testing.T, recipient *net.UnixConn) *net.UnixConn {
	t.Helper()
	payload, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, err := recipient.ReadMsgUnix(payload, control)
	must(t, err)
	if n != 1 || payload[0] != 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		t.Fatal("invalid descriptor frame")
	}
	messages, err := unix.ParseSocketControlMessage(control[:oobn])
	must(t, err)
	if len(messages) != 1 {
		t.Fatal("invalid control message count")
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	must(t, err)
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	defer func() {
		for _, fd := range fds {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}()
	if len(fds) != 1 {
		t.Fatal("descriptor count differs from OpenSSH protocol")
	}
	file := os.NewFile(uintptr(fds[0]), "delivered-stream")
	connection, err := net.FileConn(file)
	// file owns the received descriptor; avoid its finalizer closing a reused FD.
	must(t, file.Close())
	fds[0] = -1
	must(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	must(t, connection.SetDeadline(time.Now().Add(5*time.Second)))
	return connection.(*net.UnixConn)
}

func TestGuestDescriptorPassing(t *testing.T) {
	if path := os.Getenv("PORTICO_FDPASS_OTHER_UID"); path != "" {
		// The guarded root parent starts this child. The root-only marker is
		// intentionally unreadable after dropping to the adversarial UID.
		if os.Geteuid() != 1001 {
			t.Fatal("wrong fixture UID")
		}
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		if !errors.Is(PassDescriptor(context.Background(), path, os.Stdout), ErrRejected) {
			t.Fatal("other UID recipient accepted")
		}
		must(t, l.(*listener).raw.SetDeadline(time.Now().Add(100*time.Millisecond)))
		c, err := l.Accept()
		if c != nil {
			_ = c.Close()
			t.Fatal("recipient check happened after endpoint dial")
		}
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatal("invalid negative observation")
		}
		return
	}
	guest(t)
	for _, cli := range []bool{false, true} {
		name := "direct_full_duplex_after_helper_exit"
		if cli {
			name = "cli_full_duplex_after_helper_exit"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory(t), "endpoint")
			l, err := Listen(path)
			must(t, err)
			defer l.Close()
			sender, recipient := descriptorPair(t, unix.SOCK_STREAM)
			if cli {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/portico", "agent", "fdpass")
				cmd.Env = append(os.Environ(), "PORTICO_SSH_ENDPOINT="+path)
				cmd.Stdout, cmd.Stderr = sender, os.Stderr
				must(t, cmd.Run())
			} else {
				must(t, PassDescriptor(context.Background(), path, sender))
			}
			if _, err := sender.Stat(); err != nil {
				t.Fatal("caller output was closed")
			}
			must(t, sender.Close())
			client := receiveDescriptor(t, recipient)
			server, err := l.Accept()
			must(t, err)
			defer server.Close()
			must(t, server.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = client.Write([]byte("SSH-2.0-fixture\r\n\x00\xff"))
			must(t, err)
			must(t, client.CloseWrite())
			request, err := io.ReadAll(server)
			must(t, err)
			if string(request) != "SSH-2.0-fixture\r\n\x00\xff" {
				t.Fatal("delivered descriptor lost request bytes")
			}
			_, err = server.Write([]byte("response after request FIN\x00\xff"))
			must(t, err)
			must(t, server.(*net.UnixConn).CloseWrite())
			response, err := io.ReadAll(client)
			must(t, err)
			if string(response) != "response after request FIN\x00\xff" {
				t.Fatal("delivered descriptor lost final response")
			}
		})
	}
	t.Run("invalid_recipients_never_dial", func(t *testing.T) {
		path := filepath.Join(directory(t), "endpoint")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		r, w, err := os.Pipe()
		must(t, err)
		defer r.Close()
		defer w.Close()
		dgram, _ := descriptorPair(t, unix.SOCK_DGRAM)
		packet, _ := descriptorPair(t, unix.SOCK_SEQPACKET)
		tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		must(t, err)
		defer tcpListener.Close()
		tcp, err := net.DialTCP("tcp4", nil, tcpListener.Addr().(*net.TCPAddr))
		must(t, err)
		defer tcp.Close()
		tcpFile, err := tcp.File()
		must(t, err)
		defer tcpFile.Close()
		for _, output := range []*os.File{nil, w, dgram, packet, tcpFile} {
			if !errors.Is(PassDescriptor(context.Background(), path, output), ErrRejected) {
				t.Fatal("invalid recipient accepted")
			}
		}
		must(t, l.(*listener).raw.SetDeadline(time.Now().Add(100*time.Millisecond)))
		c, err := l.Accept()
		if c != nil {
			_ = c.Close()
			t.Fatal("invalid recipient triggered a dial")
		}
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatal("invalid negative observation")
		}
	})
	t.Run("other_uid_recipient_never_dials_owned_endpoint", func(t *testing.T) {
		dir := directory(t)
		must(t, os.Chown(dir, 1001, 1001))
		sender, recipient := descriptorPair(t, unix.SOCK_STREAM)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/tests/localipc", "-test.run=^TestGuestDescriptorPassing$")
		cmd.Env = append(os.Environ(), "PORTICO_FDPASS_OTHER_UID="+filepath.Join(dir, "endpoint"))
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
		cmd.Stdout, cmd.Stderr = sender, os.Stderr
		runErr := cmd.Run()
		must(t, sender.Close())
		output, readErr := io.ReadAll(recipient)
		must(t, readErr)
		if runErr != nil {
			t.Fatalf("other UID child failed: %v; %s", runErr, output)
		}
	})
	t.Run("blocked_recipient_cancellation_joins_and_closes_source", func(t *testing.T) {
		path := filepath.Join(directory(t), "endpoint")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		sender, _ := descriptorPair(t, unix.SOCK_STREAM)
		must(t, unix.SetNonblock(int(sender.Fd()), true))
		must(t, unix.SetsockoptInt(int(sender.Fd()), unix.SOL_SOCKET, unix.SO_SNDBUF, 4096))
		full := false
		for range 1024 {
			_, err := unix.Write(int(sender.Fd()), make([]byte, 4096))
			if errors.Is(err, unix.EAGAIN) {
				full = true
				break
			}
			must(t, err)
		}
		if !full {
			t.Fatal("recipient queue did not fill")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- PassDescriptor(ctx, path, sender) }()
		must(t, l.(*listener).raw.SetDeadline(time.Now().Add(5*time.Second)))
		server, err := l.Accept()
		must(t, err)
		defer server.Close()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, ErrRejected) {
				t.Fatal("canceled delivery succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("canceled send did not join")
		}
		must(t, server.SetReadDeadline(time.Now().Add(time.Second)))
		var b [1]byte
		if n, err := server.Read(b[:]); n != 0 || err != io.EOF {
			t.Fatal("canceled helper retained its source descriptor")
		}
	})
	t.Run("invalid_context_and_endpoint", func(t *testing.T) {
		sender, recipient := descriptorPair(t, unix.SOCK_STREAM)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, c := range []context.Context{nil, ctx} {
			if !errors.Is(PassDescriptor(c, "/never-contact", sender), ErrRejected) {
				t.Fatal("invalid context accepted")
			}
		}
		for _, path := range []string{"", "relative", "@abstract", "/missing/socket"} {
			if !errors.Is(PassDescriptor(context.Background(), path, sender), ErrRejected) {
				t.Fatal("unprotected endpoint accepted")
			}
		}
		must(t, recipient.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		var b [1]byte
		if _, err := recipient.Read(b[:]); err == nil {
			t.Fatal("rejected endpoint delivered data")
		}
	})
}
