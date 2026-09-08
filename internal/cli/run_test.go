package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"portico.local/portico/internal/cli"
)

func TestUnsupportedOperationsFailWithoutReflectingInput(t *testing.T) {
	for _, args := range [][]string{
		{"serve"}, {"controller", "start"}, {"connect", "192.168.50.10:8096"},
		{"enroll", "synthetic-sensitive-input"}, {"version", "--token=synthetic-sensitive-input"},
		{"version", "--json", "extra"}, {"--listen=0.0.0.0:443"}, {"\x00\n\r"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out, errout bytes.Buffer
			if code := cli.Run(args, &out, &errout); code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if out.Len() != 0 || strings.Contains(errout.String(), "synthetic-sensitive-input") {
				t.Fatal("rejected operation produced output or reflected sensitive input")
			}
			if errout.String() != "Unsupported command or arguments. Use portico help.\n" {
				t.Fatal("error response must stay generic")
			}
		})
	}
}

func TestVersionIsExplicitlyDevelopmentOnly(t *testing.T) {
	var out bytes.Buffer
	if cli.Run([]string{"version", "--json"}, &out, io.Discard) != 0 {
		t.Fatal("version failed")
	}
	var info cli.Info
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if !info.DevelopmentOnly || info.Phase != 5 || info.Version == "" || info.GoVersion == "" || info.OS == "" || info.Architecture == "" {
		t.Fatalf("missing development provenance: %+v", info)
	}
}

type brokenWriter struct{}

func TestConnectorConfigurationErrorsDoNotReflectPaths(t *testing.T) {
	var out, errout bytes.Buffer
	if code := cli.Run([]string{"connector", "run", "--config", "synthetic-sensitive-input"}, &out, &errout); code != 1 {
		t.Fatalf("configuration exit=%d", code)
	}
	if out.Len() != 0 || errout.String() != "Connector configuration rejected.\n" {
		t.Fatal("configuration error exposed input or unexpected details")
	}
}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic output failure") }

func TestOutputFailuresAreReported(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}, {"version", "--json"}} {
		if code := cli.Run(args, brokenWriter{}, io.Discard); code != 1 {
			t.Fatalf("exit = %d, want 1 for output failure", code)
		}
	}
}

func FuzzCommandSurface(f *testing.F) {
	for _, s := range []string{"serve", "version", "help", "--json", "", "\x00"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, first, second string) {
		var out, errout bytes.Buffer
		code := cli.Run([]string{first, second}, &out, &errout)
		if code != 0 && code != 2 {
			t.Fatalf("unexpected exit %d", code)
		}
		if out.Len() > 2048 || errout.Len() > 2048 {
			t.Fatal("untrusted arguments expanded output beyond the fixed command surface")
		}
		if code == 0 && (first != "version" || second != "--json") {
			t.Fatal("unsupported operation succeeded")
		}
	})
}
