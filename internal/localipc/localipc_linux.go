//go:build linux

package localipc

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/localfile"
)

// Listen creates a new 0600 pathname stream socket in an existing private 0700
// directory. Both peers must have the same effective UID. Abstract sockets, TCP,
// shared directories, symlinks and existing entries (including stale sockets)
// reject. This never deletes an existing entry to make startup succeed.
func Listen(path string) (net.Listener, error) {
	parent, name, err := localfile.OpenPrivateParent(path)
	if err != nil {
		return nil, ErrRejected
	}
	owned := false
	defer func() {
		if !owned {
			_ = parent.Close()
		}
	}()
	address, err := anchoredAddress(parent, name)
	if err != nil {
		return nil, err
	}
	// Bind resolves through the retained descriptor even if an ancestor is
	// renamed. The private parent excludes other UIDs during initial creation;
	// no process-global umask change is necessary.
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, ErrRejected
	}
	raw.SetUnlinkOnClose(false)
	var created unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &created, unix.AT_SYMLINK_NOFOLLOW) != nil || created.Mode&unix.S_IFMT != unix.S_IFSOCK || created.Uid != uint32(os.Geteuid()) || created.Nlink != 1 {
		_ = raw.Close()
		return nil, ErrRejected
	}
	l := &listener{raw: raw, parent: parent, name: name, address: path, uid: uint32(os.Geteuid()), created: created}
	owned = true
	if unix.Fchmodat(int(parent.Fd()), name, 0600, unix.AT_SYMLINK_NOFOLLOW) != nil {
		_ = l.Close()
		return nil, ErrRejected
	}
	current, err := socketEntry(parent, name, l.uid)
	if err != nil || !sameEntry(created, current) {
		_ = l.Close()
		return nil, ErrRejected
	}
	return l, nil
}

// Dial validates the pathname and actual server UID before returning a stream.
// Its five-second connection cap also applies when the caller has no deadline.
// The caller owns the returned connection; later I/O uses its own deadlines.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	parent, name, err := localfile.OpenPrivateParent(path)
	if err != nil {
		return nil, ErrRejected
	}
	defer parent.Close()
	uid := uint32(os.Geteuid())
	before, err := socketEntry(parent, name, uid)
	if err != nil {
		return nil, err
	}
	address, err := anchoredAddress(parent, name)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "unix", address)
	if err != nil {
		return nil, ErrRejected
	}
	connection, ok := raw.(*net.UnixConn)
	after, statErr := socketEntry(parent, name, uid)
	if !ok || statErr != nil || !sameEntry(before, after) || !peerOwned(connection, uid) || ctx.Err() != nil {
		_ = raw.Close()
		return nil, ErrRejected
	}
	return connection, nil
}

type listener struct {
	raw           *net.UnixListener
	parent        *os.File
	name, address string
	uid           uint32
	created       unix.Stat_t
	once          sync.Once
	closeErr      error
}

func (l *listener) Addr() net.Addr            { return &net.UnixAddr{Name: l.address, Net: "unix"} }
func (l *listener) Accept() (net.Conn, error) { return acceptOwned(l.raw, l.uid) }

// Rejected peers are closed before any application bytes are read or any
// application handler is started. No per-rejection goroutine is allocated.
func acceptOwned(raw *net.UnixListener, uid uint32) (net.Conn, error) {
	for {
		c, err := raw.AcceptUnix()
		if err != nil {
			return nil, err
		}
		if peerOwned(c, uid) {
			return c, nil
		}
		_ = c.Close()
	}
}

func (l *listener) Close() error {
	l.once.Do(func() {
		l.closeErr = l.raw.Close()
		// Unlink only our captured inode through the retained directory. A
		// renamed parent cannot redirect cleanup to a replacement directory.
		// Root and same-UID code remain trusted, including against mutation
		// between this comparison and unlinkat.
		var current unix.Stat_t
		if unix.Fstatat(int(l.parent.Fd()), l.name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && sameEntry(l.created, current) {
			if err := unix.Unlinkat(int(l.parent.Fd()), l.name, 0); err != nil {
				l.closeErr = ErrRejected
			}
		}
		if l.parent.Close() != nil {
			l.closeErr = ErrRejected
		}
	})
	return l.closeErr
}

func anchoredAddress(parent *os.File, name string) (string, error) {
	address := "/proc/self/fd/" + strconv.FormatUint(uint64(parent.Fd()), 10) + "/" + name
	// Linux sockaddr_un has 108 bytes including its terminating NUL. Do not
	// truncate a name or silently switch to the unprotected abstract namespace.
	if len(address) > 107 {
		return "", ErrRejected
	}
	return address, nil
}

func socketEntry(parent *os.File, name string, uid uint32) (unix.Stat_t, error) {
	var v unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), name, &v, unix.AT_SYMLINK_NOFOLLOW) != nil || v.Mode&unix.S_IFMT != unix.S_IFSOCK || v.Mode&07777 != 0600 || v.Uid != uid || v.Nlink != 1 {
		return unix.Stat_t{}, ErrRejected
	}
	return v, nil
}

func sameEntry(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT
}

func peerOwned(c *net.UnixConn, uid uint32) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	valid := false
	if raw.Control(func(fd uintptr) {
		v, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		valid = err == nil && v != nil && v.Pid > 0 && v.Uid == uid
	}) != nil {
		return false
	}
	return valid
}
