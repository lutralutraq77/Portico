// Package localipc provides an OS-authenticated local transport for the client
// agent. It grants no resource authority. The application protocol must bound
// requests, concurrency and lifetime and independently authorize every use.
package localipc

import "errors"

var ErrRejected = errors.New("local IPC rejected")
var ErrUnsupported = errors.New("local IPC is unsupported on this platform")
