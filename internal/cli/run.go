// Package cli implements the Phase 5 development command surface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"

	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/connector"
)

const version = "0.5.0-dev"

// Info describes a development binary. Phase is not a protocol version.
type Info struct {
	Version         string `json:"version"`
	Phase           int    `json:"phase"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	DevelopmentOnly bool   `json:"development_only"`
}

const usage = "Usage: portico version [--json]\n       portico connector run --config /absolute/path/config.json\n       portico help\nPhase 5 development only; Linux connector uses loopback control/carrier services.\n"

// Run handles a bounded command surface. Arguments are never echoed on errors,
// because future invocations may accidentally contain enrollment material.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, stdout, stderr)
}

// RunContext binds service lifetime to the caller's cancellation, including
// SIGINT/SIGTERM handled by main. No signal handlers are installed by this API.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		return 2
	}
	switch {
	case len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")):
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "version":
		if _, err := fmt.Fprintf(stdout, "Portico %s (Phase 5; development only)\n", version); err != nil {
			return 1
		}
		return 0
	case len(args) == 2 && args[0] == "version" && args[1] == "--json":
		info := Info{version, 5, runtime.Version(), runtime.GOOS, runtime.GOARCH, true}
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			return 1
		}
		return 0
	case len(args) == 4 && args[0] == "connector" && args[1] == "run" && args[2] == "--config":
		config, err := connector.LoadConfig(args[3])
		if err != nil {
			_, _ = io.WriteString(stderr, "Connector configuration rejected.\n")
			return 1
		}
		if err = config.Run(ctx); err != nil {
			message := "Connector runtime stopped after a failed security check.\n"
			if errors.Is(err, clockhealth.ErrUnavailable) {
				message = "Trusted clock health is unavailable.\n"
			}
			_, _ = io.WriteString(stderr, message)
			return 1
		}
		if _, err := io.WriteString(stdout, "Connector runtime stopped.\n"); err != nil {
			return 1
		}
		return 0
	default:
		_, _ = io.WriteString(stderr, "Unsupported command or arguments. Use portico help.\n")
		return 2
	}
}
