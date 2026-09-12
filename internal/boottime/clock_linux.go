package boottime

import (
	"math"
	"time"

	"golang.org/x/sys/unix"
)

func platformNow() (time.Duration, error) {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0, ErrUnavailable
	}
	sec, nsec := int64(ts.Sec), int64(ts.Nsec)
	if sec < 0 || nsec < 0 || nsec >= int64(time.Second) {
		return 0, ErrUnavailable
	}
	seconds, e := units(uint64(sec), time.Second)
	if e != nil || seconds > time.Duration(math.MaxInt64-nsec) {
		return 0, ErrUnavailable
	}
	return seconds + time.Duration(nsec), nil
}
