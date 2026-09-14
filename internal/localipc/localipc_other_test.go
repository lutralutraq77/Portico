//go:build !linux

package localipc

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedLocalIPC(t *testing.T) {
	if l, err := Listen("local-agent"); l != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("unsupported listener accepted")
	}
	if c, err := Dial(context.Background(), "local-agent"); c != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("unsupported dial accepted")
	}
}
