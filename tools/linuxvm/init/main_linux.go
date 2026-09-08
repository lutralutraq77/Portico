//go:build linux

// This disposable PID 1 executes cross-compiled tests on a real Linux kernel.
// It has guest loopback only, no NIC or host filesystem access.
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

func main() {
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")
	_ = syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777")
	_ = os.Setenv("TMPDIR", "/tmp")
	_ = os.Setenv("HOME", "/tmp")
	// Real issuer tests use TLS between isolated guest processes. Bringing up
	// this guest's loopback cannot create a route or listener on the host.
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if e != nil {
		panic(e)
	}
	ifr, e := unix.NewIfreq("lo")
	if e != nil {
		panic(e)
	}
	ifr.SetUint16(unix.IFF_UP | unix.IFF_LOOPBACK)
	if e = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); e != nil {
		panic(e)
	}
	// An additional TEST-NET address exercises the production literal-address
	// checks without routing to a LAN. The QEMU command has no NIC; preserve lo's
	// original 127.0.0.1 address used by the issuer and controller fixtures.
	fixture, e := unix.NewIfreq("lo:portico")
	if e != nil {
		panic(e)
	}
	if e = fixture.SetInet4Addr([]byte{192, 0, 2, 10}); e != nil {
		panic(e)
	}
	if e = unix.IoctlIfreq(fd, unix.SIOCSIFADDR, fixture); e != nil {
		panic(e)
	}
	if e = fixture.SetInet4Addr([]byte{255, 255, 255, 255}); e != nil {
		panic(e)
	}
	if e = unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, fixture); e != nil {
		panic(e)
	}
	_ = unix.Close(fd)
	if e = os.WriteFile("/portico-isolated-fixture", []byte("192.0.2.10\n"), 0600); e != nil {
		panic(e)
	}
	if e = os.Setenv("PORTICO_ISOLATED_VM", "1"); e != nil {
		panic(e)
	}
	kernel, _ := os.ReadFile("/proc/version")
	fmt.Printf("PORTICO_LINUX_RUNTIME %s/%s %s\n", runtime.GOOS, runtime.GOARCH, kernel)
	commandLine, e := os.ReadFile("/proc/cmdline")
	if e != nil {
		panic(e)
	}
	workloadOnly := false
	for _, arg := range strings.Fields(string(commandLine)) {
		if arg == "portico.workload-only=1" {
			workloadOnly = true
		}
	}
	passed := true
	tests := []struct {
		name string
		args []string
	}{
		{"/tests/cli", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/boottime", []string{"-test.v", "-test.shuffle=on", "-test.timeout=30s"}},
		{"/tests/clockhealth", []string{"-test.v", "-test.shuffle=on", "-test.timeout=30s"}},
		{"/tests/connector", []string{"-test.v", "-test.shuffle=on", "-test.timeout=30s"}},
		{"/tests/workload", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/controller", []string{"-test.v", "-test.shuffle=on", "-test.timeout=600s"}},
		{"/tests/pki", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/adminauth", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/wire", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/carrier", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/control", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/adapter", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/issuer", []string{"-test.v", "-test.shuffle=on", "-test.timeout=300s"}},
		{"/portico", []string{"version", "--json"}},
	}
	for _, test := range tests {
		if workloadOnly {
			switch test.name {
			case "/tests/boottime", "/tests/workload", "/tests/clockhealth", "/tests/connector":
			case "/tests/controller":
				test.args = []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s", "-test.run=^TestWorkloadGuest"}
			default:
				continue
			}
		}
		fmt.Printf("PORTICO_BEGIN %s\n", test.name)
		cmd := exec.Command(test.name, test.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e := cmd.Run(); e != nil {
			fmt.Printf("PORTICO_FAIL %s: %v\n", test.name, e)
			passed = false
		}
	}
	if passed {
		if workloadOnly {
			fmt.Println("PORTICO_LINUX_WORKLOAD_PASS")
		} else {
			fmt.Println("PORTICO_LINUX_ALL_PASS")
		}
	} else {
		fmt.Println("PORTICO_LINUX_FAILED")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
