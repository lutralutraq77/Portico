//go:build !linux

package agent

import "context"

func RunApplication(context.Context, Application) error { return ErrRejected }
