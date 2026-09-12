//go:build linux

package localfile

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Read requires a canonical absolute path. Every directory is opened relative
// to its already checked parent, with O_NOFOLLOW, and must be owned by root or
// the effective service UID without group/other write permission. This also
// rejects shared temporary directories, even those with the sticky bit.
// The final file must be singly linked, regular, bounded, equally owned and
// unwritable by other identities. Secret files additionally exclude group/other
// access and execution. The host administrator and this UID remain trusted.
func Read(path string, maximum int64, secret bool) ([]byte, error) {
	return readPath(path, maximum, secret, false)
}

// ReadDurable validates private state using the same protected descriptor walk
// as Read and flushes the file and parent directory before returning its bytes.
// This also reconciles a previous Create whose final directory sync failed:
// existence alone is not evidence that the state was committed durably.
func ReadDurable(path string, maximum int64) ([]byte, error) {
	return readPath(path, maximum, true, true)
}

func readPath(path string, maximum int64, secret, durable bool) ([]byte, error) {
	if maximum < 1 || maximum > MaxSize {
		return nil, ErrRejected
	}
	fd, name, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	return readFileAt(fd, name, maximum, secret, uint32(os.Geteuid()), durable)
}

// The caller owns the returned directory descriptor. Parent renames cannot
// redirect subsequent operations through another directory or symlink.
func openParent(path string) (int, string, error) {
	if len(path) == 0 || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.IndexByte(path, 0) >= 0 {
		return -1, "", ErrRejected
	}
	parts := strings.Split(path[1:], "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", ErrRejected
	}
	ownedFD := false
	defer func() {
		if !ownedFD {
			_ = unix.Close(fd)
		}
	}()
	uid := uint32(os.Geteuid())
	if !protectedDirectory(fd, uid) {
		return -1, "", ErrRejected
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, "", ErrRejected
		}
		_ = unix.Close(fd)
		fd = next
		if !protectedDirectory(fd, uid) {
			return -1, "", ErrRejected
		}
	}
	ownedFD = true
	return fd, parts[len(parts)-1], nil
}

func protectedDirectory(fd int, uid uint32) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && owned(stat.Uid, uid) && stat.Mode&0022 == 0
}
func owned(owner, uid uint32) bool { return owner == 0 || owner == uid }

func readAt(directory int, name string, maximum int64, secret bool, uid uint32) ([]byte, error) {
	return readFileAt(directory, name, maximum, secret, uid, false)
}

func readFileAt(directory int, name string, maximum int64, secret bool, uid uint32, durable bool) ([]byte, error) {
	// NONBLOCK prevents a misconfigured FIFO from hanging before fstat can
	// reject it. No bytes are read until type/ownership/mode/size checks pass.
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, ErrRejected
	}
	f := os.NewFile(uintptr(fd), "protected configuration")
	defer func() { _ = f.Close() }()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || !owned(before.Uid, uid) || before.Nlink != 1 || before.Size < 1 || before.Size > maximum || before.Mode&0022 != 0 || before.Mode&07000 != 0 || (secret && before.Mode&0177 != 0) {
		return nil, ErrRejected
	}
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || int64(len(b)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		if secret {
			clear(b)
		}
		return nil, ErrRejected
	}
	if durable && (f.Sync() != nil || unix.Fsync(directory) != nil) {
		clear(b)
		return nil, ErrRejected
	}
	return b, nil
}
