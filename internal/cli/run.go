// Package cli implements the development client and connector command surface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"portico.local/portico/internal/agent"
	"portico.local/portico/internal/client"
	"portico.local/portico/internal/clockhealth"
	"portico.local/portico/internal/connector"
	"portico.local/portico/internal/control"
	"portico.local/portico/internal/pki"
)

const version = "0.6.0-dev"

// Info describes a development binary. Phase is not a protocol version.
type Info struct {
	Version         string `json:"version"`
	Phase           int    `json:"phase"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
	DevelopmentOnly bool   `json:"development_only"`
}

const usage = "Usage: portico version [--json]\n       portico connector run --config /absolute/path/config.json\n       portico client catalog --config /absolute/path/config.json [--secrets-fd 3 | --prompt]\n       portico client connect --config /absolute/path/config.json --resource UUID --revision N [--secrets-fd 3 | --prompt]\n       portico agent run --config /absolute/path/config.json --socket /private/path/agent.sock (--secrets-fd 3 | --prompt)\n       portico agent catalog --socket /private/path/agent.sock\n       portico agent connect --socket /private/path/agent.sock --resource UUID --revision N\n       portico enroll prepare|redeem|activate --config /absolute/path/config.json (--secrets-fd 3 | --prompt)\n       portico help\nPhase 6 development only; Linux client and connector use loopback control/carrier services. Connect requires application stdin/stdout pipes. Enrollment and version 2 client identities require an explicit secret source: inherited pipe 3, or hidden foreground terminal input with --prompt.\n"

// Run handles a bounded command surface. Arguments are never echoed on errors,
// because future invocations may accidentally contain enrollment material.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, stdout, stderr)
}

// RunContext binds service lifetime to the caller's cancellation, including
// SIGINT/SIGTERM handled by main. No signal handlers are installed by this API.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return RunInputContext(ctx, args, nil, stdout, stderr)
}

// RunInputContext also supports the process-owned stdin/stdout pipe adapter.
// Successful adapter setup transfers ownership of those handles to the client.
// Resource payload is the only output written to stdout by client connect.
func RunInputContext(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if ctx == nil {
		return 2
	}
	source4, valid4 := parseSecretOption(args, 4)
	source6, valid6 := parseSecretOption(args, 6)
	source8, valid8 := parseSecretOption(args, 8)
	switch {
	case len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")):
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 1
		}
		return 0
	case valid6 && source6 != noSecretSource && args[0] == "agent" && args[1] == "run" && args[2] == "--config" && args[4] == "--socket":
		config, err := loadClientConfiguration(ctx, args[3], source6)
		if err != nil {
			_, _ = io.WriteString(stderr, "Agent configuration rejected.\n")
			return 1
		}
		if agent.Run(ctx, args[5], config) != nil {
			_, _ = io.WriteString(stderr, "Local agent stopped after a failed check.\n")
			return 1
		}
		if _, err := io.WriteString(stdout, "Local agent stopped; unlock again to start a new session.\n"); err != nil {
			return 1
		}
		return 0
	case len(args) == 4 && args[0] == "agent" && args[1] == "catalog" && args[2] == "--socket":
		resources, err := agent.Catalog(ctx, args[3])
		if err != nil {
			_, _ = io.WriteString(stderr, "Local agent catalog failed.\n")
			return 1
		}
		if json.NewEncoder(stdout).Encode(struct {
			Version   int                      `json:"version"`
			Resources []control.ResourceAccess `json:"resources"`
		}{1, resources}) != nil {
			return 1
		}
		return 0
	case len(args) == 8 && args[0] == "agent" && args[1] == "connect" && args[2] == "--socket" && args[4] == "--resource" && args[6] == "--revision":
		revision, err := strconv.ParseInt(args[7], 10, 64)
		if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != args[7] || !pki.ValidID(args[5]) {
			_, _ = io.WriteString(stderr, "Unsupported command or arguments. Use portico help.\n")
			return 2
		}
		originalOutput, ok := stdout.(*os.File)
		if !ok || stdin == nil {
			_, _ = io.WriteString(stderr, "Client requires application input/output pipes.\n")
			return 1
		}
		input, output, err := client.OpenPipes(stdin, originalOutput)
		if err != nil {
			_, _ = io.WriteString(stderr, "Client requires application input/output pipes.\n")
			return 1
		}
		_ = stdin.Close()
		_ = originalOutput.Close()
		if agent.Connect(ctx, args[3], args[5], revision, input, output) != nil {
			_, _ = io.WriteString(stderr, "Local agent resource connection failed.\n")
			return 1
		}
		return 0
	case valid4 && source4 != noSecretSource && args[0] == "enroll" && (args[1] == "prepare" || args[1] == "redeem" || args[1] == "activate") && args[2] == "--config":
		return runEnrollment(ctx, args[1], args[3], source4, stdout, stderr)
	case len(args) == 1 && args[0] == "version":
		if _, err := fmt.Fprintf(stdout, "Portico %s (Phase 6; development only)\n", version); err != nil {
			return 1
		}
		return 0
	case len(args) == 2 && args[0] == "version" && args[1] == "--json":
		info := Info{version, 6, runtime.Version(), runtime.GOOS, runtime.GOARCH, true}
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			return 1
		}
		return 0
	case valid4 && args[0] == "client" && args[1] == "catalog" && args[2] == "--config":
		config, err := loadClientConfiguration(ctx, args[3], source4)
		if err != nil {
			_, _ = io.WriteString(stderr, "Client configuration rejected.\n")
			return 1
		}
		resources, err := config.Catalog(ctx)
		if err != nil {
			return clientError(stderr, err)
		}
		if json.NewEncoder(stdout).Encode(struct {
			Version   int                      `json:"version"`
			Resources []control.ResourceAccess `json:"resources"`
		}{1, resources}) != nil {
			return 1
		}
		return 0
	case valid8 && args[0] == "client" && args[1] == "connect" && args[2] == "--config" && args[4] == "--resource" && args[6] == "--revision":
		revision, err := strconv.ParseInt(args[7], 10, 64)
		if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != args[7] || !pki.ValidID(args[5]) {
			_, _ = io.WriteString(stderr, "Unsupported command or arguments. Use portico help.\n")
			return 2
		}
		config, err := loadClientConfiguration(ctx, args[3], source8)
		if err != nil {
			_, _ = io.WriteString(stderr, "Client configuration rejected.\n")
			return 1
		}
		originalOutput, ok := stdout.(*os.File)
		if !ok || stdin == nil {
			_, _ = io.WriteString(stderr, "Client requires application input/output pipes.\n")
			return 1
		}
		input, output, err := client.OpenPipes(stdin, originalOutput)
		if err != nil {
			_, _ = io.WriteString(stderr, "Client requires application input/output pipes.\n")
			return 1
		}
		_ = stdin.Close()
		_ = originalOutput.Close()
		if err := config.Connect(ctx, args[5], revision, input, output); err != nil {
			return clientError(stderr, err)
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

func clientError(stderr io.Writer, err error) int {
	message := "Client resource connection failed.\n"
	if errors.Is(err, clockhealth.ErrUnavailable) {
		message = "Trusted clock health is unavailable.\n"
	}
	_, _ = io.WriteString(stderr, message)
	return 1
}
