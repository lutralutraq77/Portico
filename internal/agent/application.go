package agent

import (
	"os"
	"path/filepath"
	"strings"

	"portico.local/portico/internal/pki"
)

// Application selects one resource and an explicitly chosen local executable.
// Each standalone {socket} argument becomes Endpoint. Arguments are passed
// directly, without a shell. The application retains its normal OS permissions.
type Application struct {
	AgentSocket string
	Endpoint    string
	ResourceID  string
	Revision    int64
	Argv        []string
	Stdin       *os.File
	Stdout      *os.File
	Stderr      *os.File
}

func (a Application) arguments() ([]string, error) {
	canonical := func(path string) bool {
		return len(path) > 1 && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
	}
	if !canonical(a.AgentSocket) || !canonical(a.Endpoint) || a.AgentSocket == a.Endpoint || !pki.ValidID(a.ResourceID) || a.Revision < 1 || len(a.Argv) < 2 || len(a.Argv) > 64 || !canonical(a.Argv[0]) {
		return nil, ErrRejected
	}
	args := make([]string, len(a.Argv))
	bytes, replaced := 0, false
	for i, arg := range a.Argv {
		if strings.ContainsRune(arg, 0) {
			return nil, ErrRejected
		}
		if i > 0 && arg == "{socket}" {
			arg, replaced = a.Endpoint, true
		}
		bytes += len(arg)
		if bytes > 32*1024 {
			return nil, ErrRejected
		}
		args[i] = arg
	}
	if !replaced {
		return nil, ErrRejected
	}
	return args, nil
}
