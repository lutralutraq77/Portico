//go:build !linux

package client

import "os"

func OpenPipes(_, _ *os.File) (*os.File, *os.File, error) { return nil, nil, ErrConfiguration }
