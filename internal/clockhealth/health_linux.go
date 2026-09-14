//go:build linux

package clockhealth

import (
	"time"

	"golang.org/x/sys/unix"
)

// Uncertainty reads the kernel NTP status on every call, without caching. Modes
// is always zero: this operation requires no CAP_SYS_TIME and changes no clock
// parameters. maxerror, esterror and precision are microseconds, including when
// STA_NANO is set. See https://man7.org/linux/man-pages/man2/adjtimex.2.html.
func Uncertainty() (time.Duration, error) { return read(unix.Adjtimex) }

func read(adjtimex func(*unix.Timex) (int, error)) (time.Duration, error) {
	var tx unix.Timex
	state, err := adjtimex(&tx)
	const known = unix.STA_PLL | unix.STA_PPSFREQ | unix.STA_PPSTIME | unix.STA_FLL |
		unix.STA_INS | unix.STA_DEL | unix.STA_UNSYNC | unix.STA_FREQHOLD |
		unix.STA_PPSSIGNAL | unix.STA_PPSJITTER | unix.STA_PPSWANDER |
		unix.STA_PPSERROR | unix.STA_CLOCKERR | unix.STA_NANO | unix.STA_MODE | unix.STA_CLK
	const unhealthy = unix.STA_INS | unix.STA_DEL | unix.STA_UNSYNC |
		unix.STA_CLOCKERR | unix.STA_PPSJITTER | unix.STA_PPSWANDER | unix.STA_PPSERROR
	if err != nil || state != unix.TIME_OK || tx.Status & ^int32(known) != 0 || tx.Status&unhealthy != 0 ||
		(tx.Status&(unix.STA_PPSFREQ|unix.STA_PPSTIME) != 0 && tx.Status&unix.STA_PPSSIGNAL == 0) {
		return 0, ErrUnavailable
	}
	maximum, estimate, precision := int64(tx.Maxerror), int64(tx.Esterror), int64(tx.Precision)
	// Bound each operand before adding or converting. Use the maximum error,
	// never the smaller estimated error. Precision adds a conservative margin.
	const limit = int64(30 * time.Second / time.Microsecond)
	if maximum <= 0 || maximum > limit || estimate < 0 || estimate > maximum || precision <= 0 || precision > limit || maximum > limit-precision {
		return 0, ErrUnavailable
	}
	return time.Duration(maximum+precision) * time.Microsecond, nil
}
