//go:build !linux

package localipc

import (
	"context"
	"net"
)

func Listen(path string) (net.Listener, error)                { return nil, ErrUnsupported }
func Dial(ctx context.Context, path string) (net.Conn, error) { return nil, ErrUnsupported }
