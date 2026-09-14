package client

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// OpenPipes creates owned, pollable descriptions of the caller's inherited
// pipes. Reopening procfs descriptors avoids changing shared O_NONBLOCK flags
// on the original descriptions. It opens no pathname supplied by a peer.
// This initial application adapter accepts pipes; terminal/file/socket adapters
// require their own cancellation and local-user qualification.
func OpenPipes(input, output *os.File) (*os.File, *os.File, error) {
	open := func(original *os.File, flag int) (*os.File, error) {
		if original == nil {
			return nil, ErrConfiguration
		}
		raw, err := original.SyscallConn()
		if err != nil {
			return nil, ErrConfiguration
		}
		var opened *os.File
		var inner error
		err = raw.Control(func(fd uintptr) {
			var st unix.Stat_t
			if inner = unix.Fstat(int(fd), &st); inner != nil {
				return
			}
			if st.Mode&unix.S_IFMT != unix.S_IFIFO {
				inner = ErrConfiguration
				return
			}
			flags, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
			if e != nil || flags&unix.O_ACCMODE != flag {
				inner = ErrConfiguration
				return
			}
			opened, inner = os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), flag|unix.O_NONBLOCK, 0)
		})
		if err != nil || inner != nil {
			if opened != nil {
				_ = opened.Close()
			}
			return nil, ErrConfiguration
		}
		if opened.SetDeadline(time.Time{}) != nil {
			_ = opened.Close()
			return nil, ErrConfiguration
		}
		return opened, nil
	}
	in, err := open(input, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	out, err := open(output, os.O_WRONLY)
	if err != nil {
		_ = in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
