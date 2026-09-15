//go:build linux

package localfile

import (
	"os"
	"path/filepath"
	"strings"
)

// OpenDirectory returns a protected directory descriptor after Read's complete
// no-follow ancestor walk. Subsequent operations must be relative to this handle.
func OpenDirectory(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4080 || strings.ContainsRune(path, 0) {
		return nil, ErrRejected
	}
	entry := filepath.Join(path, ".portico-directory-anchor")
	if private {
		f, _, err := OpenPrivateParent(entry)
		return f, err
	}
	fd, _, err := openParent(entry)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "protected directory"), nil
}
