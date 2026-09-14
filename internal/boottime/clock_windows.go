package boottime

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Use the published API-set contract with the system-only loader. The function
// is not a kernel32 export on every supported host; do not guess its host DLL.
// https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis#apis-from-api-ms-win-core-realtime-l1-1-1dll
var interruptTime = windows.NewLazySystemDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryInterruptTimePrecise")

func platformNow() (time.Duration, error) {
	if interruptTime.Find() != nil {
		return 0, ErrUnavailable
	}
	var ticks uint64
	// The native API has a void return value; LastError is not its status.
	// LazyProc.Call marks pointer arguments as escaping across the syscall.
	_, _, _ = interruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
	return units(ticks, 100*time.Nanosecond)
}
