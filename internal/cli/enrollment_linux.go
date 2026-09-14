//go:build linux

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/enrollment"
)

// The caller owns the inherited descriptor. Reopening procfs makes a separate
// pollable description without modifying the borrowed pipe's O_NONBLOCK flag.
// Only a read pipe is accepted; files, sockets, terminals and stdio reject.
func readEnrollmentSecrets(ctx context.Context, descriptor int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || descriptor < 3 {
		return nil, enrollment.ErrRejected
	}
	var original unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(descriptor, &original) != nil || original.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, enrollment.ErrRejected
	}
	input, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", descriptor), os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, enrollment.ErrRejected
	}
	defer input.Close()
	var reopened unix.Stat_t
	raw, err := input.SyscallConn()
	if err != nil {
		return nil, enrollment.ErrRejected
	}
	var statErr error
	if raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &reopened) }) != nil || statErr != nil || original.Dev != reopened.Dev || original.Ino != reopened.Ino || reopened.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, enrollment.ErrRejected
	}
	unix.CloseOnExec(descriptor)
	if input.SetReadDeadline(time.Now().Add(30*time.Second)) != nil {
		return nil, enrollment.ErrRejected
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = input.SetReadDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(data) == 0 || len(data) > 4096 || ctx.Err() != nil {
		clear(data)
		return nil, enrollment.ErrRejected
	}
	return data, nil
}
