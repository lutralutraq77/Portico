//go:build linux

package adminapp

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/testfixture"
)

func installedFixture(t *testing.T) (string, string) {
	t.Helper()
	// Production deliberately rejects shared /tmp ancestors. Create fixtures
	// under the protected checkout (or the isolated guest's root directory).
	base, err := os.MkdirTemp(".", ".portico-admin-install-")
	testfixture.Must(t, err)
	base, err = filepath.Abs(base)
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	root, state := filepath.Join(base, "installation"), filepath.Join(base, "state")
	for _, dir := range []string{root, filepath.Join(root, "app"), filepath.Join(root, "electron"), state} {
		testfixture.Must(t, os.Mkdir(dir, 0700))
	}
	for _, name := range []string{"electron/electron", "app/main.cjs", "app/channel.cjs", "app/shell.cjs"} {
		testfixture.Must(t, os.WriteFile(filepath.Join(root, name), []byte("isolated file protection fixture, never executed"), 0600))
	}
	testfixture.Must(t, os.Chmod(filepath.Join(root, "electron/electron"), 0700))
	return root, state
}

func TestLinuxInstallationProtectionAndExclusiveState(t *testing.T) {
	root, state := installedFixture(t)
	spec, release, err := prepareTree(root, state)
	testfixture.Must(t, err)
	if spec.Executable != filepath.Join(root, "electron/electron") || spec.EntryPoint != filepath.Join(root, "app/main.cjs") || spec.StateDirectory != state {
		t.Fatal("launch escaped fixed installation members")
	}
	if _, cleanup, err := prepareTree(root, state); err != ErrRejected || cleanup != nil {
		t.Fatal("second session acquired private state")
	}
	release()
	_, release, err = prepareTree(root, state)
	testfixture.Must(t, err)
	release()
}

func TestLinuxInstallationRejectsUnprotectedMembers(t *testing.T) {
	for _, name := range []string{"writable_library", "writable_directory", "symlink_library", "hardlink_library", "fifo_library", "missing_module", "nonexecutable", "private_state", "symlink_state", "special_mode", "entry_limit"} {
		t.Run(name, func(t *testing.T) {
			root, state := installedFixture(t)
			entry := filepath.Join(root, "app/main.cjs")
			var err error
			switch name {
			case "writable_library":
				err = os.WriteFile(filepath.Join(root, "electron/injected.so"), []byte("fixture"), 0600)
				if err == nil {
					err = os.Chmod(filepath.Join(root, "electron/injected.so"), 0666)
				}
			case "writable_directory":
				err = os.Chmod(filepath.Join(root, "electron"), 0770)
			case "symlink_library":
				err = os.Symlink(entry, filepath.Join(root, "electron/injected.so"))
			case "hardlink_library":
				err = os.Link(entry, filepath.Join(root, "electron/injected.so"))
			case "fifo_library":
				err = unix.Mkfifo(filepath.Join(root, "electron/injected.so"), 0600)
			case "missing_module":
				err = os.Remove(entry)
			case "nonexecutable":
				err = os.Chmod(filepath.Join(root, "electron/electron"), 0600)
			case "private_state":
				err = os.Chmod(state, 0750)
			case "symlink_state":
				alias := state + "-alias"
				err = os.Symlink(state, alias)
				state = alias
			case "special_mode":
				err = os.Chmod(entry, 0700|os.ModeSetuid)
			case "entry_limit":
				for i := range 513 {
					err = os.WriteFile(filepath.Join(root, "electron", strconv.Itoa(i)), []byte("fixture"), 0600)
					if err != nil {
						break
					}
				}
			}
			testfixture.Must(t, err)
			if _, release, err := prepareTree(root, state); err != ErrRejected || release != nil {
				if release != nil {
					release()
				}
				t.Fatal("unsafe installation or state accepted")
			}
		})
	}
}
