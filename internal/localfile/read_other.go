//go:build !linux

package localfile

// Read requires a native ownership/permission implementation for the platform.
func Read(path string, maximum int64, secret bool) ([]byte, error) {
	return nil, ErrUnsupported
}

func ReadDurable(path string, maximum int64) ([]byte, error) { return nil, ErrUnsupported }
func Create(path string, data []byte) error                  { return ErrUnsupported }
