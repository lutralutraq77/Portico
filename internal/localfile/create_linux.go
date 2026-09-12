//go:build linux

package localfile

import (
	"crypto/rand"
	"encoding/hex"
	"os"

	"golang.org/x/sys/unix"
)

// Create commits a new private file under an existing protected directory.
// It writes a fresh 0600 file, flushes it, publishes it with RENAME_NOREPLACE,
// and flushes the containing directory. No existing name, including a symlink,
// is replaced. Unsupported filesystem operations fail without a weaker fallback.
//
// An error after publication leaves the complete file in place. The caller must
// not perform dependent network actions until ReadDurable validates and flushes
// that same state. Never delete or regenerate an enrollment key on such an error.
// Callers own data and must keep it unchanged until Create returns. This function
// enforces filesystem protection; sensitive state must be encrypted by its owner.
func Create(path string, data []byte) error {
	if len(data) == 0 || len(data) > MaxSize {
		return ErrRejected
	}
	parent, name, err := openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return createAt(parent, name, data)
}

func createAt(parent int, name string, data []byte) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrRejected
	}
	temporary := ".portico-" + hex.EncodeToString(random[:])
	if temporary == name {
		return ErrRejected
	}
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRejected
	}
	f := os.NewFile(uintptr(fd), "new protected state")
	defer func() { _ = f.Close() }()
	temporaryExists := true
	defer func() {
		if temporaryExists {
			_ = unix.Unlinkat(parent, temporary, 0)
		}
	}()
	// Set permissions only on this new inode, including with a restrictive umask.
	if f.Chmod(0600) != nil {
		return ErrRejected
	}
	if n, err := f.Write(data); err != nil || n != len(data) || f.Sync() != nil {
		return ErrRejected
	}
	if f.Close() != nil {
		return ErrRejected
	}
	if unix.Renameat2(parent, temporary, parent, name, unix.RENAME_NOREPLACE) != nil {
		return ErrRejected
	}
	temporaryExists = false
	if unix.Fsync(parent) != nil {
		return ErrRejected
	}
	return nil
}
