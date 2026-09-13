//go:build !linux

package agent

import "context"

func RunSSH(context.Context, SSH) error { return ErrRejected }
