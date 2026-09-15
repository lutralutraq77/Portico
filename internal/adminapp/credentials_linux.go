//go:build linux

package adminapp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/localfile"
)

const credentialFile = "identity.json"
const maxCredentialState = 64 * 1024

// credentialDisk owns a separate private directory lock for its complete
// lifetime. The browser state lock may be held at the same time. All I/O stays
// relative to this checked descriptor; a renamed ancestor cannot redirect it.
type credentialDisk struct {
	mu       sync.Mutex
	dir      *os.File
	poisoned bool
	// Tests inject failures at durability barriers, without weakening production.
	barrier func(string) error
}

func openCredentialDisk(state string) (*credentialDisk, error) {
	parent, err := localfile.OpenDirectory(state, true)
	if err != nil {
		return nil, ErrRejected
	}
	defer parent.Close()
	pfd := int(parent.Fd())
	err = unix.Mkdirat(pfd, "credentials", 0700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, ErrRejected
	}
	fd, err := unix.Openat(pfd, "credentials", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRejected
	}
	dir := os.NewFile(uintptr(fd), "private administrator credentials")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || dir.Sync() != nil || parent.Sync() != nil {
		_ = dir.Close()
		return nil, ErrRejected
	}
	return &credentialDisk{dir: dir, barrier: func(string) error { return nil }}, nil
}

func (d *credentialDisk) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dir != nil {
		_ = d.dir.Close()
		d.dir = nil
	}
}

// Read returns nil only for a genuinely absent record. Any unsafe entry or
// durability failure is an error, never permission to initialize a replacement.
func (d *credentialDisk) Read() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.read()
}

func (d *credentialDisk) read() ([]byte, error) {
	if d.dir == nil || d.poisoned {
		return nil, ErrRejected
	}
	var directory unix.Stat_t
	if unix.Fstat(int(d.dir.Fd()), &directory) != nil || directory.Uid != uint32(os.Geteuid()) || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Mode&07777 != 0700 {
		return nil, ErrRejected
	}
	fd, err := unix.Openat(int(d.dir.Fd()), credentialFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRejected
	}
	f := os.NewFile(uintptr(fd), "administrator credential record")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != uint32(os.Geteuid()) || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Size < 1 || before.Size > maxCredentialState {
		return nil, ErrRejected
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialState+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || f.Sync() != nil || d.dir.Sync() != nil {
		return nil, ErrRejected
	}
	return data, nil
}

// Commit flushes a fresh private inode, atomically publishes it and flushes the
// directory. The lock serializes application writers, and the expected bytes
// reject unexpected local changes. Root and this UID remain trusted. A failed
// commit poisons the handle: only closing and reopening with fresh durability
// checks can reconcile whether publication occurred. No network action may rely
// on a failed commit. This file contains public credential state, never a key.
func (d *credentialDisk) Commit(previous, next []byte) (result error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dir == nil || d.poisoned || len(next) == 0 || len(next) > maxCredentialState {
		return ErrRejected
	}
	defer func() {
		if result != nil {
			d.poisoned = true
		}
	}()
	current, err := d.read()
	if err != nil || !bytes.Equal(current, previous) {
		return ErrRejected
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return ErrRejected
	}
	temporary := ".identity-" + hex.EncodeToString(random[:])
	pfd := int(d.dir.Fd())
	fd, err := unix.Openat(pfd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRejected
	}
	f := os.NewFile(uintptr(fd), "new administrator credential record")
	defer f.Close()
	// Only our newly created temporary inode may be removed on failure.
	unpublished := true
	defer func() {
		if unpublished {
			_ = unix.Unlinkat(pfd, temporary, 0)
		}
	}()
	if f.Chmod(0600) != nil {
		return ErrRejected
	}
	if n, err := f.Write(next); err != nil || n != len(next) || d.barrier("file-sync") != nil || f.Sync() != nil || f.Close() != nil {
		return ErrRejected
	}
	flags := uint(0)
	if current == nil {
		flags = unix.RENAME_NOREPLACE
	}
	if d.barrier("publish") != nil || unix.Renameat2(pfd, temporary, pfd, credentialFile, flags) != nil {
		return ErrRejected
	}
	unpublished = false
	if d.barrier("directory-sync") != nil || d.dir.Sync() != nil {
		return ErrRejected
	}
	return nil
}
