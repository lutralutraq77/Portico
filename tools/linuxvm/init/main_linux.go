//go:build linux

// This disposable PID 1 executes cross-compiled tests on a real Linux kernel.
// It has no networking or host filesystem access.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func main() {
	_ = syscall.Mount("proc", "/proc", "proc", 0, "")
	_ = syscall.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777")
	_ = os.Setenv("TMPDIR", "/tmp")
	_ = os.Setenv("HOME", "/tmp")
	kernel, _ := os.ReadFile("/proc/version")
	fmt.Printf("PORTICO_LINUX_RUNTIME %s/%s %s\n", runtime.GOOS, runtime.GOARCH, kernel)
	passed := true
	for _, test := range []struct {
		name string
		args []string
	}{
		{"/tests/cli", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/tests/controller", []string{"-test.v", "-test.shuffle=on", "-test.timeout=180s"}},
		{"/portico", []string{"version", "--json"}},
	} {
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
		fmt.Println("PORTICO_LINUX_ALL_PASS")
	} else {
		fmt.Println("PORTICO_LINUX_FAILED")
	}
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
