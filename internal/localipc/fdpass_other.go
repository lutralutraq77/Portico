//go:build !linux

package localipc

import (
	"context"
	"os"
)

func PassDescriptor(context.Context, string, *os.File) error { return ErrRejected }
