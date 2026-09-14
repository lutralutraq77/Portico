//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/testfixture"
)

const terminalFixturePassphrase = "Terminal-κλειδί-Fixture"
const terminalFixtureSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestTerminalRejectsInvalidContextAndAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		if data, err := readTerminalSecrets(c, "client"); data != nil || err != enrollment.ErrRejected {
			t.Fatal("invalid context accepted")
		}
	}
	if data, err := readTerminalSecrets(context.Background(), "unknown"); data != nil || err != enrollment.ErrRejected {
		t.Fatal("unknown terminal operation accepted")
	}
	terminalAdmission <- struct{}{}
	defer func() { <-terminalAdmission }()
	if data, err := readTerminalSecrets(context.Background(), "client"); data != nil || err != enrollment.ErrRejected {
		t.Fatal("concurrent terminal ownership was admitted")
	}
}

func TestGuestTerminalSecrets(t *testing.T) {
	testfixture.RequireTerminalGuest(t)
	if role := os.Getenv("PORTICO_TERMINAL_TEST_CASE"); role != "" {
		terminalSecretChild(t, role)
		return
	}
	for _, name := range []string{"prepare", "redeem", "activate", "client", "line_editing", "translated_input", "limit", "oversize", "invitation_bound", "encoded_bound", "invalid_utf8", "nul", "empty", "eof", "partial_eof", "cancel", "cancel_confirmation", "interrupt", "deadline", "no_controlling_terminal", "background"} {
		t.Run(name, func(t *testing.T) {
			master, slave := testfixture.GuestTerminal(t)
			raw, err := slave.SyscallConn()
			testfixture.Must(t, err)
			settings := func() unix.Termios {
				var state *unix.Termios
				var err error
				testfixture.Must(t, raw.Control(func(fd uintptr) { state, err = unix.IoctlGetTermios(int(fd), unix.TCGETS) }))
				testfixture.Must(t, err)
				return *state
			}
			original := settings()
			if name == "translated_input" {
				original.Iflag |= unix.ISTRIP | unix.IUCLC | unix.PARMRK | unix.INPCK | unix.IGNPAR
				var err error
				testfixture.Must(t, raw.Control(func(fd uintptr) { err = unix.IoctlSetTermios(int(fd), unix.TCSETS, &original) }))
				testfixture.Must(t, err)
				original = settings()
			}
			gate, release, err := os.Pipe()
			testfixture.Must(t, err)
			defer gate.Close()
			defer release.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuestTerminalSecrets$", "-test.v")
			cmd.Env = append(os.Environ(), "PORTICO_TERMINAL_TEST_CASE="+name)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.ExtraFiles = []*os.File{gate}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: name != "no_controlling_terminal", Ctty: 0}
			testfixture.Must(t, cmd.Start())
			_ = gate.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("terminal child did not join")
					}
				}
			})
			testfixture.Must(t, master.SetDeadline(time.Now().Add(10*time.Second)))
			var transcript bytes.Buffer
			until := func(marker string) {
				t.Helper()
				for !strings.HasSuffix(transcript.String(), marker) {
					if transcript.Len() > 8192 {
						t.Fatal("terminal output exceeded fixture bound")
					}
					var b [1]byte
					_, err := io.ReadFull(master, b[:])
					if err != nil {
						t.Fatalf("terminal did not produce expected fixed marker: %v", err)
					}
					transcript.WriteByte(b[0])
				}
			}
			write := func(value []byte) { t.Helper(); _, err := master.Write(value); testfixture.Must(t, err) }
			if name != "no_controlling_terminal" && name != "background" {
				label := "Unlock passphrase: "
				if name == "prepare" || name == "encoded_bound" || name == "cancel_confirmation" {
					label = "New passphrase: "
				}
				until(label)
				if state := settings(); state.Lflag&(unix.ECHO|unix.ECHONL|unix.ECHOCTL) != 0 || state.Lflag&unix.ICANON == 0 {
					t.Fatal("secret prompt did not disable echo in canonical mode")
				}
				switch name {
				case "cancel", "deadline":
					write([]byte(terminalFixturePassphrase)) // No complete line.
					if name == "cancel" {
						testfixture.Must(t, cmd.Process.Signal(syscall.SIGTERM))
					}
				case "interrupt":
					write(append([]byte(terminalFixturePassphrase), 3))
				case "oversize":
					write([]byte(strings.Repeat("x", 1025) + "\n"))
				case "invalid_utf8":
					write([]byte{0xff, '\n'})
				case "nul":
					write([]byte{0, '\n'})
				case "encoded_bound":
					write([]byte(strings.Repeat("\"", 1024) + "\n"))
				case "empty":
					write([]byte{'\n'})
				case "eof":
					write([]byte{original.Cc[unix.VEOF]})
				case "partial_eof":
					write(append([]byte(terminalFixturePassphrase), original.Cc[unix.VEOF]))
				case "limit":
					write([]byte(strings.Repeat("x", 1024) + "\n"))
				case "line_editing":
					write(append([]byte(terminalFixturePassphrase+"界"), original.Cc[unix.VERASE], '\n'))
				default:
					write([]byte(terminalFixturePassphrase + "\n"))
				}
				if name == "prepare" || name == "encoded_bound" || name == "cancel_confirmation" {
					until("Confirm passphrase: ")
					if name == "encoded_bound" {
						write([]byte(strings.Repeat("\"", 1024) + "\n"))
					} else if name == "cancel_confirmation" {
						write([]byte(terminalFixturePassphrase))
						testfixture.Must(t, cmd.Process.Signal(syscall.SIGTERM))
					} else {
						write([]byte(terminalFixturePassphrase + "\n"))
					}
				}
				if name == "redeem" || name == "invitation_bound" {
					until("Invitation secret: ")
					value := terminalFixtureSecret
					if name == "invitation_bound" {
						value += "A"
					}
					write([]byte(value + "\n"))
				}
			}
			until("TERMINAL_FIXTURE_OK")
			if settings() != original {
				t.Fatal("terminal attributes were not exactly restored")
			}
			if bytes.Contains(transcript.Bytes(), []byte(terminalFixturePassphrase)) || bytes.Contains(transcript.Bytes(), []byte(terminalFixtureSecret)) || bytes.Contains(transcript.Bytes(), []byte(strings.Repeat("x", 16))) {
				t.Fatal("secret material echoed to the terminal")
			}
			// While the session leader is alive, finish any discarded partial
			// line. Only this new newline may be readable after restoration.
			if name == "cancel" || name == "cancel_confirmation" || name == "deadline" || name == "oversize" || name == "invitation_bound" {
				readback, err := os.OpenFile(slave.Name(), os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
				testfixture.Must(t, err)
				defer readback.Close()
				testfixture.Must(t, readback.SetReadDeadline(time.Now().Add(time.Second)))
				write([]byte{'\n'})
				var discarded [64]byte
				n, err := readback.Read(discarded[:])
				testfixture.Must(t, err)
				if n != 1 || discarded[0] != '\n' {
					t.Fatal("abandoned secret input survived terminal restoration")
				}
			}
			_, err = release.Write([]byte{1})
			testfixture.Must(t, err)
			select {
			case err := <-done:
				joined = true
				testfixture.Must(t, err)
			case <-time.After(3 * time.Second):
				t.Fatal("terminal child did not exit after release")
			}
		})
	}
}

func terminalSecretChild(t *testing.T, name string) {
	if name == "background_holder" {
		terminalFixtureRelease(t)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if name == "deadline" {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, time.Second)
		defer stop()
	}
	operation := "client"
	if name == "prepare" || name == "redeem" || name == "activate" {
		operation = name
	}
	if name == "encoded_bound" || name == "cancel_confirmation" {
		operation = "prepare"
	}
	if name == "invitation_bound" {
		operation = "redeem"
	}
	read := readTerminalSecrets
	if name == "background" {
		read = func(ctx context.Context, _ string) ([]byte, error) { return terminalBackgroundRead(t, ctx) }
	}
	data, err := read(ctx, operation)
	defer clear(data)
	wantError := name == "oversize" || name == "invitation_bound" || name == "encoded_bound" || name == "invalid_utf8" || name == "nul" || name == "empty" || name == "eof" || name == "partial_eof" || name == "cancel" || name == "cancel_confirmation" || name == "interrupt" || name == "deadline" || name == "no_controlling_terminal" || name == "background"
	if wantError {
		if data != nil || err != enrollment.ErrRejected {
			t.Fatal("rejected terminal input returned data")
		}
	} else {
		testfixture.Must(t, err)
		var fields map[string]string
		testfixture.Must(t, json.Unmarshal(data, &fields))
		passphrase := terminalFixturePassphrase
		if name == "limit" {
			passphrase = strings.Repeat("x", 1024)
		}
		if fields["passphrase"] != passphrase || (name == "prepare" && fields["confirmation"] != passphrase) || (name == "redeem" && fields["invitation_secret"] != terminalFixtureSecret) {
			t.Fatal("terminal input changed secret bytes")
		}
		count := 1
		if name == "prepare" || name == "redeem" {
			count = 2
		}
		if len(fields) != count {
			t.Fatal("terminal supplied fields outside the operation")
		}
	}
	fmt.Fprintln(os.Stdout, "TERMINAL_FIXTURE_OK")
	terminalFixtureRelease(t)
}

func terminalFixtureRelease(t *testing.T) {
	t.Helper()
	gate := os.NewFile(3, "terminal-fixture-release")
	defer gate.Close()
	var release [1]byte
	_, err := io.ReadFull(gate, release[:])
	testfixture.Must(t, err)
}

func terminalBackgroundRead(t *testing.T, ctx context.Context) ([]byte, error) {
	t.Helper()
	gate, release, err := os.Pipe()
	testfixture.Must(t, err)
	defer gate.Close()
	defer release.Close()
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	holder := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestGuestTerminalSecrets$")
	holder.Env = append(os.Environ(), "PORTICO_TERMINAL_TEST_CASE=background_holder")
	holder.ExtraFiles = []*os.File{gate}
	holder.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	testfixture.Must(t, holder.Start())
	_ = gate.Close()
	defer func() { _, _ = release.Write([]byte{1}); testfixture.Must(t, holder.Wait()) }()
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|unix.O_NOCTTY, 0)
	testfixture.Must(t, err)
	defer terminal.Close()
	raw, err := terminal.SyscallConn()
	testfixture.Must(t, err)
	foreground := func(group int) {
		var err error
		testfixture.Must(t, raw.Control(func(fd uintptr) { err = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPGRP, group) }))
		testfixture.Must(t, err)
	}
	// This fixture process alone changes foreground ownership. Ignore SIGTTOU
	// here so it can restore that ownership after testing the real rejection.
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	foreground(holder.Process.Pid)
	defer foreground(unix.Getpgrp())
	return readTerminalSecrets(ctx, "client")
}
