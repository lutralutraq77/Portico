//go:build !linux

package cli

import (
	"context"
	"portico.local/portico/internal/enrollment"
)

func readEnrollmentSecrets(context.Context, int) ([]byte, error) { return nil, enrollment.ErrRejected }
