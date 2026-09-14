//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/enrollment"
)

// One prompt owns terminal settings at a time; callers never queue passwords.
var terminalAdmission = make(chan struct{}, 1)

// Input is taken only from this process's foreground controlling terminal.
// Application pipes, inherited secret pipes, arguments and environment remain
// independent. No terminal path or prompt text is accepted from configuration.
func readTerminalSecrets(parent context.Context, operation string) (data []byte, resultErr error) {
	if parent == nil || parent.Err() != nil || (operation != "prepare" && operation != "redeem" && operation != "activate" && operation != "client") {
		return nil, enrollment.ErrRejected
	}
	select {
	case terminalAdmission <- struct{}{}:
	default:
		return nil, enrollment.ErrRejected
	}
	defer func() { <-terminalAdmission }()
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, enrollment.ErrRejected
	}
	defer terminal.Close()
	info, err := terminal.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil, enrollment.ErrRejected
	}
	raw, err := terminal.SyscallConn()
	if err != nil {
		return nil, enrollment.ErrRejected
	}
	control := func(action func(int) error) error {
		var actionErr error
		if err := raw.Control(func(fd uintptr) { actionErr = action(int(fd)) }); err != nil {
			return err
		}
		return actionErr
	}
	var original *unix.Termios
	if control(func(fd int) error {
		group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		if err != nil || group != unix.Getpgrp() {
			return enrollment.ErrRejected
		}
		original, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	}) != nil {
		return nil, enrollment.ErrRejected
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if terminal.SetDeadline(deadline) != nil {
		return nil, enrollment.ErrRejected
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = terminal.SetDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
		// Flush queued input while echo is still disabled, including an
		// overlong/abandoned line. Restore even when reading or flushing fails.
		flushErr := control(func(fd int) error { return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) })
		restoreErr := control(func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, original) })
		if flushErr != nil || restoreErr != nil || ctx.Err() != nil {
			clear(data)
			data, resultErr = nil, enrollment.ErrRejected
		}
	}()
	settings := *original
	settings.Lflag &^= unix.ECHO | unix.ECHONL | unix.ECHOE | unix.ECHOK | unix.ECHOKE | unix.ECHOCTL | unix.ECHOPRT | unix.IEXTEN
	settings.Lflag |= unix.ICANON | unix.ISIG
	// Preserve UTF-8 bytes even when the caller used seven-bit, parity-marked
	// or lowercase-converting input. Terminal editing remains canonical.
	settings.Iflag &^= unix.IGNCR | unix.INLCR | unix.IXON | unix.IXOFF | unix.ISTRIP | unix.PARMRK | unix.INPCK | unix.IGNPAR | unix.IUCLC
	settings.Iflag |= unix.ICRNL | unix.IUTF8
	settings.Cc[unix.VINTR] = 3 // Ctrl+C reaches main's cancellation handler.
	settings.Cc[unix.VQUIT] = 0 // Do not request a Go stack dump from secret input.
	settings.Cc[unix.VSUSP] = 0 // Typed Ctrl+Z must not suspend with echo disabled.
	if control(func(fd int) error {
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &settings); err != nil {
			return err
		}
		return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
	}) != nil {
		return nil, enrollment.ErrRejected
	}
	fields := make(map[string]string, 2)
	read := func(field, label string, limit int) error {
		value, err := readTerminalLine(ctx, terminal, label, limit)
		if err != nil {
			return err
		}
		defer clear(value)
		fields[field] = string(value)
		return nil
	}
	label := "Unlock passphrase: "
	if operation == "prepare" {
		label = "New passphrase: "
	}
	if read("passphrase", label, 1024) != nil {
		return nil, enrollment.ErrRejected
	}
	if operation == "prepare" && read("confirmation", "Confirm passphrase: ", 1024) != nil {
		return nil, enrollment.ErrRejected
	}
	if operation == "redeem" && read("invitation_secret", "Invitation secret: ", 43) != nil {
		return nil, enrollment.ErrRejected
	}
	data, err = json.Marshal(fields)
	if err != nil || len(data) > 4096 || ctx.Err() != nil {
		clear(data)
		return nil, enrollment.ErrRejected
	}
	return data, nil
}

func readTerminalLine(ctx context.Context, terminal *os.File, label string, limit int) ([]byte, error) {
	if _, err := io.WriteString(terminal, label); err != nil {
		return nil, enrollment.ErrRejected
	}
	defer func() { _, _ = io.WriteString(terminal, "\n") }()
	buffer := make([]byte, limit+1)
	defer clear(buffer)
	// Canonical mode returns at most one line. A short record without newline
	// is terminal EOF; a full buffer without newline is overlong. Neither is
	// joined to a later line, and neither can be silently truncated into a key.
	n, err := terminal.Read(buffer)
	if err != nil || n == 0 || buffer[n-1] != '\n' {
		return nil, enrollment.ErrRejected
	}
	value := buffer[:n-1]
	if len(value) == 0 || len(value) > limit || !utf8.Valid(value) || bytes.ContainsAny(value, "\x00\r\n") || ctx.Err() != nil {
		return nil, enrollment.ErrRejected
	}
	return bytes.Clone(value), nil
}
