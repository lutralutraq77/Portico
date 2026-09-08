// Package localfile reads bounded, locally protected service configuration.
// It does not create files, follow symbolic links or repair permissions.
package localfile

import "errors"

var ErrRejected = errors.New("local configuration file rejected")
var ErrUnsupported = errors.New("local configuration protection unsupported")

const MaxSize = 1024 * 1024
