//go:build linux

package localfile

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenPrivateParent anchors a canonical absolute entry path in an existing
// directory owned by the effective UID with mode 0700. Ancestors follow Read's
// protected traversal rules. The caller owns the returned directory descriptor;
// operations must remain relative to it, not repeat the original path lookup.
// It creates nothing and never repairs existing permissions or ownership.
func OpenPrivateParent(path string) (*os.File, string, error) {
	fd, name, err := openParent(path)
	if err != nil {
		return nil, "", err
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return nil, "", ErrRejected
	}
	return os.NewFile(uintptr(fd), "protected private directory"), name, nil
}
