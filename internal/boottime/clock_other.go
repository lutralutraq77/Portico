//go:build !linux && !windows

package boottime

import "time"

func platformNow() (time.Duration, error) { return 0, ErrUnavailable }
