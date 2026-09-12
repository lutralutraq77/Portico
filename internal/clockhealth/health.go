// Package clockhealth reads the local operating system's UTC health assessment.
// It does not synchronize time or authenticate a time source. The host's time
// service and kernel are part of the trusted computing base.
package clockhealth

import "errors"

// ErrUnavailable means that no usable bound was established. Callers must stop
// authorizing/forwarding on this error; zero is never a fallback bound.
var ErrUnavailable = errors.New("trusted clock health unavailable")
