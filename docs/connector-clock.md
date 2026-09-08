# Connector elapsed clock

The internal/boottime component reads a native elapsed clock that includes suspend. The workload runtime uses it for request-start lease deadlines, checks before forwarding and independent shutdown of blocked I/O. Physical suspend/hibernate qualification remains pending. Readings are not serialized, persisted or accepted from the network.

Linux uses CLOCK_BOOTTIME, which continues across suspend. CLOCK_MONOTONIC stops during suspend and is unsuitable for this requirement. [Linux timekeeping documentation](https://docs.kernel.org/core-api/timekeeping.html).

Windows uses QueryInterruptTimePrecise in 100-nanosecond units. Ordinary interrupt time includes sleep/hibernation; the unbiased variant excludes it. [Interrupt-time semantics](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time), [precise API](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise). The system-only DLL loader resolves the published api-ms-win-core-realtime-l1-1-1.dll contract. A runtime test found no direct kernel32 export on this host, so relying on that implementation DLL failed. The API-set contract is listed in Microsoft's [Windows API inventory](https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis#apis-from-api-ms-win-core-realtime-l1-1-1dll).

Missing APIs, failed native reads and conversion overflow return an error. Unsupported platforms have no fallback. The workload runtime invalidates sessions on error or decreasing time, and after restart. The elapsed-clock component alone does not establish UTC accuracy or clock-health evidence, enforce lease deadlines, or prove physical suspend behavior. Go timers alone cannot establish the resume boundary.

## Linux UTC health

The separate internal/clockhealth.Uncertainty provider reads Linux adjtimex with a zero Modes field on every call. This operation reads kernel clock state without changing time, synchronization flags or any other parameters, and requires no CAP_SYS_TIME. It returns the kernel maximum-error estimate plus precision, both interpreted in microseconds even in nanosecond mode. [Linux adjtimex interface](https://man7.org/linux/man-pages/man2/adjtimex.2.html).

The provider rejects syscall failures, any state other than TIME_OK, unsynchronized/hardware/PPS error flags, missing requested PPS signals, leap-second transition flags, unknown flags and invalid/inconsistent/overflowing error bounds. Bounds must be positive and at most thirty seconds including precision; a short workload lease will reject much smaller unusable bounds. There is no cached healthy result. Platforms without an implemented provider return an error.

This is the trusted local kernel's assessment, not independent authentication of its upstream time source. The operator must qualify the host time service and synchronization configuration. Portico does not configure that service or set the clock. The workload clock adds sample duration and a one-millisecond margin, compares elapsed and UTC progress, and latches failure. The connector pool checks the same health while idle and terminates on failure. Recovery requires a new runtime; old sessions never resume.

Tests supply synthetic kernel responses for conversion/error paths. The NIC-less Linux guest separately executes the real read-only syscall and requires its unsynchronized initial kernel state to be rejected. Healthy forwarding fixtures still use an explicit twenty-millisecond test bound: they do not establish real NTP accuracy. No host or guest clock state is modified by the provider tests, and physical suspend, Windows health and deployment time-service qualification remain open.
