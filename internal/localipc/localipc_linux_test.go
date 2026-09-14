//go:build linux

package localipc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/testfixture"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func guest(t *testing.T) {
	t.Helper()
	testfixture.RequireTerminalGuest(t)
	if os.Geteuid() != 0 {
		t.Fatal("requires disposable guest root")
	}
}

func directory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/", "portico-ipc-")
	must(t, err)
	t.Cleanup(func() { must(t, os.RemoveAll(dir)) })
	return dir
}

func rejectedDial(t *testing.T, path string) {
	t.Helper()
	c, err := Dial(context.Background(), path)
	if c != nil {
		_ = c.Close()
		t.Fatal("unsafe IPC connection returned")
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func rejectedListen(t *testing.T, path string) {
	t.Helper()
	l, err := Listen(path)
	if l != nil {
		_ = l.Close()
		t.Fatal("unsafe IPC listener returned")
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func TestLocalIPCInvalidContextAndPaths(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if c, err := Dial(ctx, "/never-contact"); c != nil || !errors.Is(err, ErrRejected) {
			t.Fatal("invalid context accepted")
		}
	}
	for _, path := range []string{"", "relative", "@abstract", "/", "//bad", "/a/../b", "/a/./b", "/a/", "/a/\x00b", "/" + strings.Repeat("a", 4096)} {
		rejectedListen(t, path)
		rejectedDial(t, path)
	}
}

func TestGuestLocalIPC(t *testing.T) {
	guest(t)
	t.Run("concurrent_startup_has_one_owner", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		results := make(chan net.Listener, 16)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() { l, _ := Listen(path); results <- l })
		}
		wg.Wait()
		close(results)
		owners := 0
		for l := range results {
			if l != nil {
				owners++
				must(t, l.Close())
			}
		}
		if owners != 1 {
			t.Fatalf("concurrent owners: %d", owners)
		}
	})
	t.Run("long_parent_path_uses_retained_descriptor", func(t *testing.T) {
		dir := filepath.Join(directory(t), strings.Repeat("a", 150))
		must(t, os.Mkdir(dir, 0700))
		path := filepath.Join(dir, "agent.sock")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		c, err := Dial(context.Background(), path)
		must(t, err)
		defer c.Close()
		s, err := l.Accept()
		must(t, err)
		defer s.Close()
	})
	t.Run("full_duplex_half_close_and_socket_mode", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		var stat unix.Stat_t
		must(t, unix.Lstat(path, &stat))
		if stat.Mode&07777 != 0600 || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
			t.Fatal("unsafe created socket")
		}
		if l.Addr().Network() != "unix" || l.Addr().String() != path {
			t.Fatal("incorrect public address")
		}
		c, err := Dial(context.Background(), path)
		must(t, err)
		defer c.Close()
		s, err := l.Accept()
		must(t, err)
		defer s.Close()
		must(t, c.SetDeadline(time.Now().Add(2*time.Second)))
		must(t, s.SetDeadline(time.Now().Add(2*time.Second)))
		_, err = c.Write([]byte("request"))
		must(t, err)
		must(t, c.(*net.UnixConn).CloseWrite())
		b, err := io.ReadAll(s)
		must(t, err)
		if string(b) != "request" {
			t.Fatal("request payload corrupted")
		}
		_, err = s.Write([]byte("response after request EOF"))
		must(t, err)
		must(t, s.(*net.UnixConn).CloseWrite())
		b, err = io.ReadAll(c)
		must(t, err)
		if string(b) != "response after request EOF" {
			t.Fatal("half-close lost final response")
		}
	})
	t.Run("close_unblocks_accept_and_removes_socket", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		l, err := Listen(path)
		must(t, err)
		done := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if c != nil {
				c.Close()
			}
			done <- err
		}()
		must(t, l.Close())
		must(t, l.Close())
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("accept not interrupted: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("accept blocked after close")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned socket remains after close")
		}
	})
	for _, kind := range []string{"file", "symlink", "directory", "fifo", "stale_socket", "active_socket"} {
		t.Run("preserve_existing_"+kind, func(t *testing.T) {
			path := filepath.Join(directory(t), "agent.sock")
			switch kind {
			case "file":
				must(t, os.WriteFile(path, []byte("preserve"), 0600))
			case "symlink":
				must(t, os.Symlink("missing", path))
			case "directory":
				must(t, os.Mkdir(path, 0700))
			case "fifo":
				must(t, unix.Mkfifo(path, 0600))
			case "stale_socket", "active_socket":
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				must(t, err)
				l.SetUnlinkOnClose(false)
				defer l.Close()
				if kind == "stale_socket" {
					must(t, l.Close())
				}
			}
			before, err := os.Lstat(path)
			must(t, err)
			rejectedListen(t, path)
			after, err := os.Lstat(path)
			must(t, err)
			if !os.SameFile(before, after) {
				t.Fatal("existing entry replaced")
			}
			rejectedDial(t, path) // Existing raw sockets are deliberately not mode 0600.
		})
	}
	for _, mode := range []os.FileMode{0755, 0770, 0777, 0700 | os.ModeSetgid} {
		t.Run("reject_parent_mode_"+mode.String(), func(t *testing.T) {
			dir := directory(t)
			must(t, os.Chmod(dir, mode))
			path := filepath.Join(dir, "agent.sock")
			rejectedListen(t, path)
			rejectedDial(t, path)
		})
	}
	t.Run("reject_symlink_ancestor", func(t *testing.T) {
		dir := directory(t)
		must(t, os.Mkdir(filepath.Join(dir, "private"), 0700))
		must(t, os.Symlink("private", filepath.Join(dir, "link")))
		path := filepath.Join(dir, "link", "agent.sock")
		rejectedListen(t, path)
		rejectedDial(t, path)
	})
	t.Run("reject_shared_tmp_ancestor", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.sock")
		rejectedListen(t, path)
		rejectedDial(t, path)
	})
	t.Run("reject_foreign_parent", func(t *testing.T) {
		dir := directory(t)
		must(t, os.Chown(dir, 65534, 65534))
		path := filepath.Join(dir, "agent.sock")
		rejectedListen(t, path)
		rejectedDial(t, path)
	})
	t.Run("reject_long_socket_name", func(t *testing.T) {
		path := filepath.Join(directory(t), strings.Repeat("s", 108))
		rejectedListen(t, path)
	})
	t.Run("reject_changed_socket_permissions_and_owner", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		must(t, os.Chmod(path, 0666))
		rejectedDial(t, path)
		must(t, os.Chmod(path, 0600))
		must(t, os.Chown(path, 65534, 65534))
		rejectedDial(t, path)
	})
	t.Run("cleanup_preserves_replacement_entry", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		l, err := Listen(path)
		must(t, err)
		must(t, os.Remove(path))
		must(t, os.WriteFile(path, []byte("replacement"), 0600))
		must(t, l.Close())
		b, err := os.ReadFile(path)
		must(t, err)
		if string(b) != "replacement" {
			t.Fatal("replacement removed")
		}
	})
	t.Run("cleanup_follows_owned_directory_after_rename", func(t *testing.T) {
		dir := directory(t)
		original := filepath.Join(dir, "private")
		moved := filepath.Join(dir, "moved")
		must(t, os.Mkdir(original, 0700))
		l, err := Listen(filepath.Join(original, "agent.sock"))
		must(t, err)
		must(t, os.Rename(original, moved))
		must(t, os.Mkdir(original, 0700))
		replacement := filepath.Join(original, "agent.sock")
		must(t, os.WriteFile(replacement, []byte("replacement"), 0600))
		must(t, l.Close())
		if _, err := os.Lstat(filepath.Join(moved, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned socket not removed")
		}
		b, err := os.ReadFile(replacement)
		must(t, err)
		if string(b) != "replacement" {
			t.Fatal("replacement directory affected")
		}
	})
}

// Each helper is a real process running as UID/GID 65534 in the disposable
// guest. A retained guard descriptor proves the fixture even when that user
// cannot read the root-owned marker's pathname.
func helper(t *testing.T, mode, path string) *exec.Cmd {
	t.Helper()
	guard, err := os.Open("/portico-isolated-fixture")
	must(t, err)
	t.Cleanup(func() { guard.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalIPCProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "PORTICO_LOCALIPC_HELPER="+mode, "PORTICO_LOCALIPC_PATH="+path)
	cmd.ExtraFiles = []*os.File{guard}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	return cmd
}

func TestGuestLocalIPCPeerCredentials(t *testing.T) {
	guest(t)
	t.Run("other_user_cannot_connect_to_private_endpoint", func(t *testing.T) {
		path := filepath.Join(directory(t), "agent.sock")
		l, err := Listen(path)
		must(t, err)
		defer l.Close()
		out, err := helper(t, "private-denied", path).CombinedOutput()
		if err != nil {
			t.Fatalf("foreign process: %s: %v", out, err)
		}
	})
	t.Run("foreign_peer_rejected_before_application_accept", func(t *testing.T) {
		dir := directory(t)
		must(t, os.Chmod(dir, 0755))
		path := filepath.Join(dir, "raw.sock")
		raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		must(t, err)
		defer raw.Close()
		must(t, os.Chmod(path, 0666))
		accepted := make(chan net.Conn, 1)
		errs := make(chan error, 1)
		go func() {
			c, err := acceptOwned(raw, 0)
			if err != nil {
				errs <- err
			} else {
				accepted <- c
			}
		}()
		out, err := helper(t, "raw-connect", path).CombinedOutput()
		if err != nil {
			t.Fatalf("foreign process: %s: %v", out, err)
		}
		select {
		case c := <-accepted:
			c.Close()
			t.Fatal("foreign peer reached application")
		case err := <-errs:
			t.Fatal(err)
		default:
		}
		c, err := net.DialTimeout("unix", path, time.Second)
		must(t, err)
		defer c.Close()
		select {
		case s := <-accepted:
			defer s.Close()
			if !peerOwned(s.(*net.UnixConn), 0) {
				t.Fatal("wrong peer accepted")
			}
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(2 * time.Second):
			t.Fatal("valid peer starved after rejection")
		}
	})
	t.Run("socket_owner_cannot_substitute_for_actual_server_uid", func(t *testing.T) {
		dir := directory(t)
		must(t, os.Chmod(dir, 0777))
		path := filepath.Join(dir, "raw.sock")
		cmd := helper(t, "raw-server", path)
		stdout, err := cmd.StdoutPipe()
		must(t, err)
		cmd.Stderr = os.Stderr
		must(t, cmd.Start())
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		r := bufio.NewReader(stdout)
		for {
			line, err := r.ReadString('\n')
			must(t, err)
			if strings.TrimSpace(line) == "PORTICO_FOREIGN_SERVER_READY" {
				break
			}
		}
		// Give the path the caller's exact expected ownership after the other
		// user has called listen. Only actual SO_PEERCRED can detect the mismatch.
		must(t, os.Chmod(dir, 0700))
		must(t, os.Chown(path, 0, 0))
		must(t, os.Chmod(path, 0600))
		rejectedDial(t, path)
		_, err = io.Copy(io.Discard, r)
		must(t, err)
		must(t, cmd.Wait())
	})
}

func TestLocalIPCProcessHelper(t *testing.T) {
	mode := os.Getenv("PORTICO_LOCALIPC_HELPER")
	if mode == "" {
		t.Skip("subprocess helper only")
	}
	if os.Getenv("PORTICO_ISOLATED_VM") != "1" || os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("missing isolated process guard")
	}
	guard := os.NewFile(3, "isolated guard")
	defer guard.Close()
	b, err := io.ReadAll(io.LimitReader(guard, 64))
	must(t, err)
	if string(b) != "192.0.2.10\n" {
		t.Fatal("invalid guard contents")
	}
	interfaces, err := net.Interfaces()
	must(t, err)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			t.Fatal("non-loopback interface")
		}
	}
	path := os.Getenv("PORTICO_LOCALIPC_PATH")
	switch mode {
	case "private-denied":
		c, err := net.DialTimeout("unix", path, time.Second)
		if c != nil {
			c.Close()
			t.Fatal("other user reached private socket")
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("denial not filesystem permission: %v", err)
		}
	case "raw-connect":
		c, err := net.DialTimeout("unix", path, time.Second)
		must(t, err)
		defer c.Close()
		must(t, c.SetDeadline(time.Now().Add(time.Second)))
		_, _ = c.Write([]byte("untrusted application payload"))
		var b [1]byte
		_, err = c.Read(b[:])
		if err == nil {
			t.Fatal("foreign peer received application bytes")
		}
	case "raw-server":
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		must(t, err)
		l.SetUnlinkOnClose(false)
		defer l.Close()
		_, err = io.WriteString(os.Stdout, "PORTICO_FOREIGN_SERVER_READY\n")
		must(t, err)
		c, err := l.Accept()
		must(t, err)
		defer c.Close()
		must(t, c.SetReadDeadline(time.Now().Add(time.Second)))
		var b [1]byte
		n, err := c.Read(b[:])
		if n != 0 || err == nil {
			t.Fatal("client sent bytes before server UID check")
		}
	default:
		t.Fatal("unknown helper mode")
	}
}
