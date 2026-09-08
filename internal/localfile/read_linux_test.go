//go:build linux

package localfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadAtNativeProtections(t *testing.T) {
	for _, name := range []string{"public", "secret", "secret_group_read", "group_write", "other_write", "executable_secret", "empty", "oversized", "symlink", "hardlink", "fifo", "directory", "foreign_owner"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input")
			if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			secret := false
			switch name {
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "secret":
				secret = true
			case "secret_group_read":
				secret = true
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "group_write":
				if err := os.Chmod(path, 0620); err != nil {
					t.Fatal(err)
				}
			case "other_write":
				if err := os.Chmod(path, 0602); err != nil {
					t.Fatal(err)
				}
			case "executable_secret":
				secret = true
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.Truncate(path, 33); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, filepath.Join(dir, "target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "foreign_owner":
				if os.Geteuid() != 0 {
					t.Skip("changing fixture ownership requires isolated root")
				}
				if err := os.Chown(path, 65534, -1); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if !protectedDirectory(fd, uint32(os.Geteuid())) {
				t.Fatal("fixture directory is unprotected")
			}
			b, err := readAt(fd, "input", 32, secret, uint32(os.Geteuid()))
			if name == "public" || name == "secret" {
				if err != nil || string(b) != "fixture" {
					t.Fatalf("protected read: %q %v", b, err)
				}
			} else if b != nil || !errors.Is(err, ErrRejected) {
				t.Fatalf("unsafe file accepted: %q %v", b, err)
			}
		})
	}
}

func TestCanonicalPathAndBoundsDeniedBeforeRead(t *testing.T) {
	for _, path := range []string{"", "relative", "/", "//etc/file", "/etc/../etc/file", "/etc/./file", "/etc/file/", "/etc/\x00file"} {
		if b, err := Read(path, 32, true); b != nil || !errors.Is(err, ErrRejected) {
			t.Fatalf("accepted noncanonical path %q", path)
		}
	}
	for _, maximum := range []int64{-1, 0, MaxSize + 1} {
		if b, err := Read("/never-read", maximum, true); b != nil || !errors.Is(err, ErrRejected) {
			t.Fatalf("accepted size %d", maximum)
		}
	}
}

func TestGuestProtectedPathTraversal(t *testing.T) {
	if os.Getenv("PORTICO_ISOLATED_VM") != "1" {
		t.Skip("requires the disposable guest root filesystem")
	}
	marker, err := os.ReadFile("/portico-isolated-fixture")
	if err != nil || string(marker) != "192.0.2.10\n" || os.Geteuid() != 0 {
		t.Fatal("missing disposable guest guard")
	}
	dir, err := os.MkdirTemp("/", "portico-localfile-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	child := filepath.Join(dir, "private")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(child, "key")
	if err := os.WriteFile(path, []byte("fixture only"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(path, 32, true); err != nil || string(b) != "fixture only" {
		t.Fatalf("native protected traversal: %q %v", b, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(filepath.Join(link, "key"), 32, true); b != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("followed directory symlink")
	}
	if err := os.Chmod(child, 0770); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(path, 32, true); b != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("traversed group-writable directory")
	}
	if err := os.Chmod(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(child, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(path, 32, true); b != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("traversed foreign-owned directory")
	}
	if err := os.Chown(child, 0, -1); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(shared, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(shared, 32, true); b != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("traversed shared temporary directory")
	}
}
