// Package cli implements only the Phase 4 development command surface.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
)

const version = "0.4.0-dev"

// Info describes a development binary. Phase is not a protocol version.
type Info struct {
	Version         string `json:"version"`
	Phase           int    `json:"phase"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	DevelopmentOnly bool   `json:"development_only"`
}

const usage = "Usage: portico version [--json]\n       portico help\nPhase 4 development foundation; no network service is available.\n"

// Run handles a bounded command surface. Arguments are never echoed on errors,
// because future invocations may accidentally contain enrollment material.
func Run(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")):
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "version":
		if _, err := fmt.Fprintf(stdout, "Portico %s (Phase 4; development only)\n", version); err != nil {
			return 1
		}
		return 0
	case len(args) == 2 && args[0] == "version" && args[1] == "--json":
		info := Info{version, 4, runtime.Version(), runtime.GOOS, runtime.GOARCH, true}
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			return 1
		}
		return 0
	default:
		_, _ = io.WriteString(stderr, "Unsupported command or arguments. Use portico help.\n")
		return 2
	}
}
