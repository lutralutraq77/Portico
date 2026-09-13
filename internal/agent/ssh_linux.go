//go:build linux

package agent

import (
	"context"
	"os"
)

// RunSSH supervises the foreground OpenSSH process and every protected local
// resource stream. A successful remote exit cannot hide a failed final RPC.
func RunSSH(ctx context.Context, s SSH) error {
	helper, err := os.Executable()
	if err != nil {
		return ErrRejected
	}
	a, args, err := s.application(helper)
	if err != nil {
		return ErrRejected
	}
	return runApplication(ctx, a, args, sshEnvironment(os.Environ(), s.Endpoint, helper))
}
