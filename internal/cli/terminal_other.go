//go:build !linux

package cli

import (
	"context"

	"portico.local/portico/internal/enrollment"
)

func readTerminalSecrets(context.Context, string) ([]byte, error) {
	return nil, enrollment.ErrRejected
}
