package cli

import (
	"context"

	"portico.local/portico/internal/enrollment"
)

type secretSource uint8

const (
	noSecretSource secretSource = iota
	pipeSecretSource
	terminalSecretSource
)

// Only exact, mutually exclusive suffixes are accepted. No descriptor, prompt
// text, password or terminal path can be supplied by an untrusted argument.
func parseSecretOption(args []string, base int) (secretSource, bool) {
	switch {
	case len(args) == base:
		return noSecretSource, true
	case len(args) == base+1 && args[base] == "--prompt":
		return terminalSecretSource, true
	case len(args) == base+2 && args[base] == "--secrets-fd" && args[base+1] == "3":
		return pipeSecretSource, true
	default:
		return noSecretSource, false
	}
}

func readCommandSecrets(ctx context.Context, operation string, source secretSource) ([]byte, error) {
	switch source {
	case pipeSecretSource:
		return readEnrollmentSecrets(ctx, 3)
	case terminalSecretSource:
		return readTerminalSecrets(ctx, operation)
	default:
		return nil, enrollment.ErrRejected
	}
}
