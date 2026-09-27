//go:build linux

package adminapp

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/adminbridge"
	"portico.local/portico/internal/localfile"
)

const installation = "/usr/lib/portico-admin"

func prepareInstalled(state string) (adminbridge.Launch, func(), error) {
	return prepareTree(installation, state)
}

// A protected installation is trusted local code, including Electron's adjacent
// libraries and application modules. Check the whole bounded tree, not just the
// entry point. Root and this UID remain trusted against concurrent replacement.
func prepareTree(root, state string) (adminbridge.Launch, func(), error) {
	dir, err := localfile.OpenDirectory(root, false)
	if err != nil {
		return adminbridge.Launch{}, nil, ErrRejected
	}
	defer dir.Close()
	remaining := 512
	bytes := int64(768 * 1024 * 1024)
	found := make(map[string]uint32)
	if inspectTree(dir, "", 0, &remaining, &bytes, found) != nil {
		return adminbridge.Launch{}, nil, ErrRejected
	}
	for _, name := range []string{"electron/electron", "app/main.cjs", "app/channel.cjs", "app/shell.cjs"} {
		mode, ok := found[name]
		if !ok || (name == "electron/electron" && mode&0100 == 0) {
			return adminbridge.Launch{}, nil, ErrRejected
		}
	}
	private, err := localfile.OpenDirectory(state, true)
	if err != nil {
		return adminbridge.Launch{}, nil, ErrRejected
	}
	// Lock the directory itself: no attacker-selectable lock file or stale lock
	// deletion. Another application using this state fails before key unlock.
	if unix.Flock(int(private.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = private.Close()
		return adminbridge.Launch{}, nil, ErrRejected
	}
	release := func() { _ = private.Close() }
	return adminbridge.Launch{Executable: filepath.Join(root, "electron/electron"), EntryPoint: filepath.Join(root, "app/main.cjs"), StateDirectory: state}, release, nil
}

func inspectTree(dir *os.File, prefix string, depth int, remaining *int, bytes *int64, found map[string]uint32) error {
	if depth > 5 {
		return ErrRejected
	}
	entries, err := dir.ReadDir(*remaining + 1)
	if err != nil && err != io.EOF {
		return ErrRejected
	}
	for _, entry := range entries {
		*remaining--
		if *remaining < 0 {
			return ErrRejected
		}
		fd, err := unix.Openat(int(dir.Fd()), entry.Name(), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
		if err != nil {
			return ErrRejected
		}
		file := os.NewFile(uintptr(fd), "protected administrator installation")
		err = inspectEntry(file, prefix+entry.Name(), depth, remaining, bytes, found)
		_ = file.Close()
		if err != nil {
			return ErrRejected
		}
	}
	return nil
}

func inspectEntry(file *os.File, name string, depth int, remaining *int, bytes *int64, found map[string]uint32) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Mode&0022 != 0 {
		return ErrRejected
	}
	// Chromium's one sandbox helper may be installed setuid by root. No other
	// special mode is accepted, including on directories or application scripts.
	if stat.Mode&07000 != 0 && !(name == "electron/chrome-sandbox" && stat.Uid == 0 && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&07777 == 04755) {
		return ErrRejected
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return inspectTree(file, name+"/", depth+1, remaining, bytes, found)
	case unix.S_IFREG:
		if stat.Nlink != 1 || stat.Size < 0 {
			return ErrRejected
		}
		*bytes -= stat.Size
		if *bytes < 0 {
			return ErrRejected
		}
		found[name] = stat.Mode
		return nil
	default:
		return ErrRejected
	}
}
