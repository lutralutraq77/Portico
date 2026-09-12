//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portico.local/portico/internal/enrollment"
)

func TestSecretPipeOwnershipBoundsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		content   []byte
		wantError bool
	}{
		{"complete", []byte(`{"passphrase":"fixture only"}`), false},
		{"empty", nil, true},
		{"oversized", bytes.Repeat([]byte("a"), 4097), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			descriptor := int(reader.Fd())
			before, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			written := make(chan struct{})
			go func() { defer close(written); _, _ = writer.Write(tc.content); _ = writer.Close() }()
			data, err := readEnrollmentSecrets(context.Background(), descriptor)
			defer clear(data)
			if tc.wantError {
				if data != nil || err != enrollment.ErrRejected {
					t.Fatal("invalid secret pipe accepted")
				}
			} else if err != nil || !bytes.Equal(data, tc.content) {
				t.Fatalf("pipe rejected: %v", err)
			}
			after, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
			if err != nil || before != after {
				t.Fatal("borrowed pipe closed or flags changed")
			}
			_ = reader.Close()
			<-written
		})
	}
	t.Run("cancellation_after_partial_input", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		if _, err = writer.Write([]byte("partial secret")); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan struct{})
		descriptor := int(reader.Fd())
		go func() {
			defer close(finished)
			data, err := readEnrollmentSecrets(ctx, descriptor)
			if data != nil || err != enrollment.ErrRejected {
				t.Error("cancelled read returned secret data")
			}
		}()
		deadline := time.Now().Add(2 * time.Second)
		for {
			remaining, err := unix.IoctlGetInt(descriptor, unix.TIOCINQ)
			if err != nil {
				t.Fatal(err)
			}
			if remaining == 0 {
				break
			}
			select {
			case <-finished:
				t.Fatal("secret read ended before consuming partial input")
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("secret read did not consume partial input")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("secret input ignored cancellation")
		}
	})
	t.Run("directions_and_regular_files", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		file, err := os.CreateTemp(t.TempDir(), "ordinary-file")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		for _, fd := range []int{0, 1, 2, -1, int(writer.Fd()), int(file.Fd())} {
			if data, err := readEnrollmentSecrets(context.Background(), fd); data != nil || err != enrollment.ErrRejected {
				t.Fatal("unsupported secret descriptor accepted")
			}
		}
	})
}
