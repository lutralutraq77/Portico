//go:build linux

package localipc

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// PassDescriptor connects to a protected endpoint and sends the connected
// descriptor using OpenSSH's ProxyUseFdpass protocol. The recipient must be a
// connected Unix stream with the same effective UID, checked before dialing.
// It duplicates output; the caller retains ownership of that file. Delivery
// does not establish resource authorization or successful stream completion.
func PassDescriptor(ctx context.Context, path string, output *os.File) error {
	if ctx == nil || ctx.Err() != nil || output == nil {
		return ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rawOutput, err := net.FileConn(output)
	if err != nil {
		return ErrRejected
	}
	defer rawOutput.Close()
	recipient, ok := rawOutput.(*net.UnixConn)
	if !ok || recipient.LocalAddr().Network() != "unix" || !peerOwned(recipient, uint32(os.Geteuid())) {
		return ErrRejected
	}
	deadline, _ := ctx.Deadline()
	if recipient.SetWriteDeadline(deadline) != nil {
		return ErrRejected
	}
	// A canceled send must not retain a descriptor or leave a worker behind.
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = recipient.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	connection, err := Dial(ctx, path)
	if err != nil {
		return ErrRejected
	}
	defer connection.Close()
	source, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrRejected
	}
	fd, err := source.SyscallConn()
	if err != nil {
		return ErrRejected
	}
	sent := false
	if fd.Control(func(value uintptr) {
		if ctx.Err() != nil {
			return
		}
		rights := unix.UnixRights(int(value))
		n, oobn, err := recipient.WriteMsgUnix([]byte{0}, rights, nil)
		sent = err == nil && n == 1 && oobn == len(rights)
	}) != nil || !sent || ctx.Err() != nil {
		return ErrRejected
	}
	return nil
}
