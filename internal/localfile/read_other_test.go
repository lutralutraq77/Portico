//go:build !linux

package localfile

import (
	"errors"
	"testing"
)

func TestUnsupportedDoesNotRead(t *testing.T) {
	if b, err := Read("unused", 32, true); b != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported read: bytes=%d error=%v", len(b), err)
	}
	if b, err := ReadDurable("unused", 32); b != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("unsupported durable read accepted")
	}
	if err := Create("unused", []byte("fixture")); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unsupported protected create accepted")
	}
}
