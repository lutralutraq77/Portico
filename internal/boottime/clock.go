// Package boottime reads an OS elapsed clock that includes system suspend.
// Readings are process-local deadline inputs, never persisted lease authority.
package boottime

import (
	"errors"
	"math"
	"time"
)

var ErrUnavailable = errors.New("suspend-aware clock unavailable")

// Now returns elapsed time since boot, including suspend/hibernation, using
// CLOCK_BOOTTIME on Linux or QueryInterruptTimePrecise on Windows. There is no
// fallback to a clock that stops during suspend. Callers must close authority
// on any error, decreasing reading, restart or failed external clock-health
// check. This function alone neither verifies UTC nor enforces a socket lease.
func Now() (time.Duration, error) { return platformNow() }

func units(value uint64, unit time.Duration) (time.Duration, error) {
	if unit <= 0 || value > math.MaxInt64/uint64(unit) {
		return 0, ErrUnavailable
	}
	return time.Duration(value) * unit, nil
}
