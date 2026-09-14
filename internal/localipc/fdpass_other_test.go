//go:build !linux

package localipc

import (
	"context"
	"errors"
	"testing"
)

func TestDescriptorPassingUnsupported(t *testing.T) {
	if !errors.Is(PassDescriptor(context.Background(), "/unused", nil), ErrRejected) {
		t.Fatal("unsupported descriptor adapter accepted")
	}
}
