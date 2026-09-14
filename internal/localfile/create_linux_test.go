//go:build linux

package localfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func privateTestDirectory(t *testing.T) (string, int) {
	t.Helper()
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return dir, fd
}

func TestCreateConcurrentAttemptsCannotReplaceWinner(t *testing.T) {
	dir, fd := privateTestDirectory(t)
	const count = 16
	errorsByWriter := make([]error, count)
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() { errorsByWriter[i] = createAt(fd, "attempt", []byte(fmt.Sprintf("attempt %d", i))) })
	}
	workers.Wait()
	winner := -1
	for i, err := range errorsByWriter {
		if err == nil {
			if winner != -1 {
				t.Fatal("multiple creators reported a committed attempt")
			}
			winner = i
		} else if !errors.Is(err, ErrRejected) {
			t.Fatal(err)
		}
	}
	if winner < 0 {
		t.Fatal("no attempt committed")
	}
	data, err := readFileAt(fd, "attempt", 128, true, uint32(os.Geteuid()), true)
	if err != nil || string(data) != fmt.Sprintf("attempt %d", winner) {
		t.Fatalf("winning state was replaced: %q %v", data, err)
	}
	info, err := os.Stat(filepath.Join(dir, "attempt"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private mode: %v %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "attempt" {
		t.Fatalf("left temporary files: %v %v", entries, err)
	}
}

func TestCreatePreservesExistingNamesAndOutsideFiles(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "hardlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir, fd := privateTestDirectory(t)
			original := filepath.Join(dir, "original")
			if err := os.WriteFile(original, []byte("existing protected state"), 0600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "target")
			var err error
			switch kind {
			case "regular":
				err = os.WriteFile(target, []byte("first attempt"), 0600)
			case "symlink":
				err = os.Symlink(original, target)
			case "hardlink":
				err = os.Link(original, target)
			case "directory":
				err = os.Mkdir(target, 0700)
			case "fifo":
				err = unix.Mkfifo(target, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := createAt(fd, "target", []byte("replacement")); !errors.Is(err, ErrRejected) {
				t.Fatalf("existing name replaced: %v", err)
			}
			after, err := os.Lstat(target)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("existing inode changed")
			}
			data, err := os.ReadFile(original)
			if err != nil || string(data) != "existing protected state" {
				t.Fatal("outside file changed")
			}
			if kind == "regular" {
				data, err = os.ReadFile(target)
				if err != nil || string(data) != "first attempt" {
					t.Fatal("first attempt overwritten")
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatal("failed create left temporary files")
			}
		})
	}
}

func TestCreateAndDurableReadRejectUnsafePaths(t *testing.T) {
	for _, path := range []string{"", "relative", "/", "//etc/file", "/etc/../etc/file", "/etc/./file", "/etc/file/", "/etc/\x00file"} {
		if err := Create(path, []byte("fixture")); !errors.Is(err, ErrRejected) {
			t.Fatalf("created noncanonical path %q", path)
		}
		if data, err := ReadDurable(path, 32); data != nil || !errors.Is(err, ErrRejected) {
			t.Fatalf("durable read accepted %q", path)
		}
	}
	for _, data := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, MaxSize+1)} {
		if err := Create("/never-created", data); !errors.Is(err, ErrRejected) {
			t.Fatal("accepted invalid data size")
		}
	}
	for _, maximum := range []int64{0, -1, MaxSize + 1} {
		if data, err := ReadDurable("/never-read", maximum); data != nil || !errors.Is(err, ErrRejected) {
			t.Fatal("accepted invalid read bound")
		}
	}
}

func TestDirectorySyncFailurePreservesPublishedAttemptForReconciliation(t *testing.T) {
	dir, directory := privateTestDirectory(t)
	// O_PATH permits openat/renameat2 but cannot be fsynced. Exercise an actual
	// post-publication syscall failure, without replacing production operations.
	unflushable, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(unflushable)
	const original = "the same generated key and attempt"
	if err := createAt(unflushable, "attempt", []byte(original)); !errors.Is(err, ErrRejected) {
		t.Fatal("reported success without directory durability")
	}
	if data, err := readFileAt(unflushable, "attempt", 128, true, uint32(os.Geteuid()), true); data != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("returned state without completing its durability barrier")
	}
	data, err := readFileAt(directory, "attempt", 128, true, uint32(os.Geteuid()), true)
	if err != nil || string(data) != original {
		t.Fatalf("lost published state after sync failure: %q %v", data, err)
	}
	if err := createAt(directory, "attempt", []byte("another key")); !errors.Is(err, ErrRejected) {
		t.Fatal("reconciliation replaced the first attempt")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "attempt" {
		t.Fatal("reconciliation left other state files")
	}
}

func TestGuestProtectedStateCreationAndDurableRead(t *testing.T) {
	if os.Getenv("PORTICO_ISOLATED_VM") != "1" {
		t.Skip("requires disposable guest root")
	}
	marker, err := os.ReadFile("/portico-isolated-fixture")
	if err != nil || string(marker) != "192.0.2.10\n" || os.Geteuid() != 0 {
		t.Fatal("missing disposable guest guard")
	}
	dir, err := os.MkdirTemp("/", "portico-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "attempt")
	if err := Create(path, []byte("encrypted fixture bytes")); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadDurable(path, 32); err != nil || string(data) != "encrypted fixture bytes" {
		t.Fatalf("durable state: %q %v", data, err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := Create(filepath.Join(link, "redirected"), []byte("fixture")); !errors.Is(err, ErrRejected) {
		t.Fatal("followed parent symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "redirected")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("symlink create wrote a file")
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if err := Create(filepath.Join(dir, "shared"), []byte("fixture")); !errors.Is(err, ErrRejected) {
		t.Fatal("created in writable parent")
	}
	if data, err := ReadDurable(path, 32); data != nil || !errors.Is(err, ErrRejected) {
		t.Fatal("read state through writable parent")
	}
}
