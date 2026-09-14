//go:build linux

package clockhealth

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelHealthValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*unix.Timex) (int, error)
		want   time.Duration
	}{
		{"microseconds", nil, 20001 * time.Microsecond},
		{"nanosecond_mode_keeps_error_units", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_NANO; return 0, nil }, 20001 * time.Microsecond},
		{"pps_signal", func(tx *unix.Timex) (int, error) {
			tx.Status |= unix.STA_PPSFREQ | unix.STA_PPSTIME | unix.STA_PPSSIGNAL
			return 0, nil
		}, 20001 * time.Microsecond},
		{"syscall_error", func(*unix.Timex) (int, error) { return 0, unix.EPERM }, 0},
		{"unsynchronized", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_UNSYNC; return 0, nil }, 0},
		{"hardware_fault", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_CLOCKERR; return 0, nil }, 0},
		{"leap_insert_flag", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_INS; return 0, nil }, 0},
		{"leap_delete_flag", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_DEL; return 0, nil }, 0},
		{"pps_missing", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_PPSFREQ; return 0, nil }, 0},
		{"pps_jitter", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_PPSJITTER; return 0, nil }, 0},
		{"pps_wander", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_PPSWANDER; return 0, nil }, 0},
		{"pps_error", func(tx *unix.Timex) (int, error) { tx.Status |= unix.STA_PPSERROR; return 0, nil }, 0},
		{"unknown_flag", func(tx *unix.Timex) (int, error) { tx.Status |= 1 << 16; return 0, nil }, 0},
		{"negative_status", func(tx *unix.Timex) (int, error) { tx.Status = -1; return 0, nil }, 0},
		{"zero_maximum", func(tx *unix.Timex) (int, error) { tx.Maxerror = 0; return 0, nil }, 0},
		{"negative_maximum", func(tx *unix.Timex) (int, error) { tx.Maxerror = -1; return 0, nil }, 0},
		{"excessive_maximum", func(tx *unix.Timex) (int, error) { tx.Maxerror = 30000001; return 0, nil }, 0},
		{"negative_estimate", func(tx *unix.Timex) (int, error) { tx.Esterror = -1; return 0, nil }, 0},
		{"estimate_exceeds_maximum", func(tx *unix.Timex) (int, error) { tx.Esterror = tx.Maxerror + 1; return 0, nil }, 0},
		{"zero_precision", func(tx *unix.Timex) (int, error) { tx.Precision = 0; return 0, nil }, 0},
		{"negative_precision", func(tx *unix.Timex) (int, error) { tx.Precision = -1; return 0, nil }, 0},
		{"excessive_precision", func(tx *unix.Timex) (int, error) { tx.Precision = 30000001; return 0, nil }, 0},
		{"combined_limit", func(tx *unix.Timex) (int, error) { tx.Maxerror = 30000000; return 0, nil }, 0},
		{"exact_limit", func(tx *unix.Timex) (int, error) { tx.Maxerror = 29999999; return 0, nil }, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := read(func(tx *unix.Timex) (int, error) {
				if *tx != (unix.Timex{}) {
					t.Fatal("native call was not an empty read-only request")
				}
				tx.Maxerror, tx.Esterror, tx.Precision, tx.Status = 20000, 10, 1, unix.STA_PLL
				if tc.change != nil {
					return tc.change(tx)
				}
				return unix.TIME_OK, nil
			})
			if got != tc.want || (tc.want == 0 && !errors.Is(err, ErrUnavailable)) || (tc.want != 0 && err != nil) {
				t.Fatalf("bound=%v error=%v, want %v", got, err, tc.want)
			}
		})
	}
	for _, state := range []int{unix.TIME_INS, unix.TIME_DEL, unix.TIME_OOP, unix.TIME_WAIT, unix.TIME_ERROR, -1, 6} {
		if got, err := read(func(tx *unix.Timex) (int, error) {
			tx.Maxerror, tx.Precision = 20000, 1
			return state, nil
		}); got != 0 || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("accepted state %d: %v, %v", state, got, err)
		}
	}
}

func TestHealthIsReadAgainAfterFailureAndRecovery(t *testing.T) {
	calls := 0
	native := func(tx *unix.Timex) (int, error) {
		if *tx != (unix.Timex{}) {
			t.Fatal("read-only request reused prior output")
		}
		calls++
		tx.Maxerror, tx.Precision = 10000, 1
		if calls == 2 {
			return unix.TIME_ERROR, nil
		}
		return unix.TIME_OK, nil
	}
	for _, healthy := range []bool{true, false, true} {
		_, err := read(native)
		if (err == nil) != healthy {
			t.Fatalf("call %d: %v", calls, err)
		}
	}
}

func TestNativeKernelHealthReadOnly(t *testing.T) {
	// This test never changes kernel time or synchronization metadata. A fresh
	// NIC-less guest has no time synchronizer and must be rejected as unhealthy.
	var tx unix.Timex
	state, syscallErr := unix.Adjtimex(&tx)
	bound, err := Uncertainty()
	t.Logf("native kernel state=%d status=%#x maxerror_us=%d precision_us=%d syscall=%v bound=%v health=%v", state, tx.Status, tx.Maxerror, tx.Precision, syscallErr, bound, err)
	if os.Getenv("PORTICO_ISOLATED_VM") == "1" {
		marker, markerErr := os.ReadFile("/portico-isolated-fixture")
		if markerErr != nil || string(marker) != "192.0.2.10\n" {
			t.Fatal("missing isolated guest marker")
		}
		if syscallErr != nil || state != unix.TIME_ERROR || tx.Status&unix.STA_UNSYNC == 0 || !errors.Is(err, ErrUnavailable) || bound != 0 {
			t.Fatal("fresh unsynchronized guest did not establish native fail-closed behavior")
		}
	} else if err != nil {
		if bound != 0 || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid failure %v, %v", bound, err)
		}
	} else if bound <= 0 || bound > 30*time.Second {
		t.Fatalf("invalid native bound: %v", bound)
	}
}
