// Package localfile reads bounded, locally protected service configuration and
// creates immutable private state. It never follows symbolic links, overwrites
// an existing state file or repairs permissions on caller-owned files.
package localfile

import "errors"

var ErrRejected = errors.New("local configuration file rejected")
var ErrUnsupported = errors.New("local configuration protection unsupported")

const MaxSize = 1024 * 1024
