//go:build !linux

package clockhealth

import "time"

// Uncertainty fails closed until this platform has a qualified native provider.
func Uncertainty() (time.Duration, error) { return 0, ErrUnavailable }
