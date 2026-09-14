//go:build linux

package testfixture

import (
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func RequireTerminalGuest(t *testing.T) {
	t.Helper()
	if os.Getenv("PORTICO_ISOLATED_VM") != "1" {
		t.Skip("requires isolated Linux guest terminal devices")
	}
	marker, err := os.ReadFile("/portico-isolated-fixture")
	if err != nil || string(marker) != "192.0.2.10\n" {
		t.Fatal("missing isolated terminal fixture guard")
	}
	interfaces, err := net.Interfaces()
	Must(t, err)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			t.Fatal("terminal fixture has a non-loopback interface")
		}
	}
}

// GuestTerminal allocates private PTY handles in the guest's own devpts mount.
// Creating a controlling terminal remains an explicit child-process action.
func GuestTerminal(t *testing.T) (master, slave *os.File) {
	t.Helper()
	RequireTerminalGuest(t)
	master, err := os.OpenFile("/dev/pts/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	Must(t, err)
	t.Cleanup(func() { _ = master.Close() })
	raw, err := master.SyscallConn()
	Must(t, err)
	var number int
	var ioctlErr error
	Must(t, raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0)
		if ioctlErr == nil {
			number, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	}))
	Must(t, ioctlErr)
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	Must(t, err)
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}
