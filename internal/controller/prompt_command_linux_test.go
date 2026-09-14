//go:build linux

package controller

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/testfixture"
)

// The terminal is inherited at fd 3, while stdin/stdout remain distinct
// application pipes. --prompt must open /dev/tty, never treat fd 3 as secrets.
func guestPromptApplication(t *testing.T, secret any, args ...string) *guestApplication {
	t.Helper()
	requireWorkloadGuest(t)
	fields, ok := secret.(map[string]string)
	if !ok || len(args) < 6 || args[len(args)-2] != "--secrets-fd" || args[len(args)-1] != "3" {
		t.Fatal("invalid prompt fixture input")
	}
	master, slave := testfixture.GuestTerminal(t)
	raw, err := slave.SyscallConn()
	must(t, err)
	settings := func(t *testing.T) unix.Termios {
		t.Helper()
		var state *unix.Termios
		var err error
		must(t, raw.Control(func(fd uintptr) { state, err = unix.IoctlGetTermios(int(fd), unix.TCGETS) }))
		must(t, err)
		return *state
	}
	original := settings(t)
	invocation := append(append([]string{}, args[:len(args)-2]...), "--prompt")
	p := guestStartConfiguredApplication(t, []*os.File{slave}, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}, invocation...)
	var transcript bytes.Buffer
	p.terminalCheck = func(t *testing.T) {
		t.Helper()
		if settings(t) != original {
			t.Fatal("actual CLI did not restore terminal attributes")
		}
		must(t, master.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		tail, err := io.ReadAll(io.LimitReader(master, 8193))
		if err != nil && !os.IsTimeout(err) && !errors.Is(err, syscall.EIO) {
			t.Fatal("cannot inspect completed CLI terminal output")
		}
		if len(tail)+transcript.Len() > 8192 {
			t.Fatal("CLI terminal output exceeded bound")
		}
		transcript.Write(tail)
		for _, value := range fields {
			if value != "" && bytes.Contains(transcript.Bytes(), []byte(value)) {
				t.Fatal("actual CLI echoed secret input")
			}
		}
	}
	labels := []struct{ field, prompt string }{{"passphrase", "Unlock passphrase: "}}
	if args[0] == "enroll" && args[1] == "prepare" {
		labels = []struct{ field, prompt string }{{"passphrase", "New passphrase: "}, {"confirmation", "Confirm passphrase: "}}
	} else if args[0] == "enroll" && args[1] == "redeem" {
		labels = append(labels, struct{ field, prompt string }{"invitation_secret", "Invitation secret: "})
	}
	if len(labels) != len(fields) {
		t.Fatal("prompt fixture cannot represent extra JSON fields")
	}
	must(t, master.SetDeadline(time.Now().Add(10*time.Second)))
	for _, label := range labels {
		for !bytes.HasSuffix(transcript.Bytes(), []byte(label.prompt)) {
			if transcript.Len() > 8192 {
				t.Fatal("CLI prompt exceeded output bound")
			}
			var b [1]byte
			if _, err := io.ReadFull(master, b[:]); err != nil {
				t.Fatal("actual CLI did not request terminal input")
			}
			transcript.WriteByte(b[0])
		}
		if settings(t).Lflag&(unix.ECHO|unix.ECHONL) != 0 {
			t.Fatal("actual CLI requested a secret with echo enabled")
		}
		value, ok := fields[label.field]
		if !ok {
			t.Fatal("missing terminal fixture input")
		}
		_, err := master.Write([]byte(value + "\n"))
		must(t, err)
	}
	return p
}
