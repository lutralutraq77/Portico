//go:build !linux

package clockhealth

import (
	"errors"
	"testing"
)

func TestUnsupportedFailsClosed(t *testing.T) {
	if bound, err := Uncertainty(); bound != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsupported clock returned %v, %v", bound, err)
	}
}
