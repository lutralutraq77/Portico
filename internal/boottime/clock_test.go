package boottime

import (
	"math"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNativeClockAdvancesAndConcurrentReads(t *testing.T) {
	first, e := Now()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "android" {
		if e != ErrUnavailable || first != 0 {
			t.Fatal("unsupported platform fell back to an unqualified clock")
		}
		return
	}
	if e != nil || first <= 0 {
		t.Fatal("native suspend-aware clock unavailable")
	}
	time.Sleep(20 * time.Millisecond)
	second, e := Now()
	if e != nil || second-first < 10*time.Millisecond {
		t.Fatal("native clock did not advance")
	}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Go(func() {
			previous := second
			for j := 0; j < 256; j++ {
				current, e := Now()
				if e != nil || current < previous {
					t.Error("native clock failed or decreased")
					return
				}
				previous = current
			}
		})
	}
	workers.Wait()
}

func TestNativeUnitConversionRejectsOverflow(t *testing.T) {
	for _, unit := range []time.Duration{time.Nanosecond, 100 * time.Nanosecond, time.Second} {
		limit := uint64(math.MaxInt64) / uint64(unit)
		if _, e := units(limit, unit); e != nil {
			t.Fatal("last representable native count rejected")
		}
		if got, e := units(limit+1, unit); e == nil || got != 0 {
			t.Fatal("native count overflow became a new deadline")
		}
	}
	for _, unit := range []time.Duration{0, -1} {
		if got, e := units(1, unit); e == nil || got != 0 {
			t.Fatal("invalid native time unit accepted")
		}
	}
}
