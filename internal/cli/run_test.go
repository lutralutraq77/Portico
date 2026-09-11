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
		{"client", "connect", "--config", "synthetic-sensitive-input", "--resource", "192.0.2.10:443", "--revision", "1"},
		{"client", "connect", "--config", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "01"},
		{"client", "connect", "--config", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "9223372036854775808"},
		{"enroll", "prepare", "--config", "synthetic-sensitive-input", "--secrets-fd", "0"},
		{"enroll", "redeem", "--config", "synthetic-sensitive-input", "--secrets-fd", "1"},
		{"enroll", "activate", "--config", "synthetic-sensitive-input", "--secrets-fd", "03"},
		{"enroll", "reset", "--config", "synthetic-sensitive-input", "--secrets-fd", "3"},
		{"enroll", "redeem", "--config", "synthetic-sensitive-input", "--token", "synthetic-sensitive-input"},
		{"client", "catalog", "--config", "synthetic-sensitive-input", "--secrets-fd", "0"},
		{"client", "catalog", "--config", "synthetic-sensitive-input", "--secrets-fd", "03"},
		{"client", "catalog", "--config", "synthetic-sensitive-input", "--prompt", "--secrets-fd", "3"},
		{"client", "catalog", "--config", "synthetic-sensitive-input", "--prompt=synthetic-sensitive-input"},
		{"agent", "run", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input"},
		{"agent", "run", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input", "--secrets-fd", "0"},
		{"agent", "run", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input", "--prompt", "--secrets-fd", "3"},
		{"agent", "catalog", "--socket", "synthetic-sensitive-input", "--prompt"},
		{"agent", "daemon", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input", "--prompt"},
		{"agent", "unlock", "--socket", "synthetic-sensitive-input"},
		{"agent", "unlock", "--socket", "synthetic-sensitive-input", "--secrets-fd", "0"},
		{"agent", "unlock", "--socket", "synthetic-sensitive-input", "--prompt", "--secrets-fd", "3"},
		{"agent", "lock", "--socket", "synthetic-sensitive-input", "--secrets-fd", "3"},
		{"agent", "status", "--socket", "synthetic-sensitive-input", "--config", "synthetic-sensitive-input"},
		{"agent", "connect", "--socket", "synthetic-sensitive-input", "--resource", "192.0.2.10:443", "--revision", "1"},
		{"agent", "connect", "--socket", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "01"},
		{"agent", "connect", "--socket", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "1", "--prompt"},
		{"agent", "exec", "--socket", "synthetic-sensitive-input", "--resource", "192.0.2.10:443", "--revision", "1", "--endpoint", "synthetic-sensitive-input", "--", "/usr/bin/curl", "{socket}"},
		{"agent", "exec", "--socket", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "01", "--endpoint", "synthetic-sensitive-input", "--", "/usr/bin/curl", "{socket}"},
		{"enroll", "prepare", "--config", "synthetic-sensitive-input", "--secrets-fd", "3", "--prompt"},
		{"client", "connect", "--config", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "1", "--secrets-fd", "1"},
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
	if !info.DevelopmentOnly || info.Phase != 6 || info.Version == "" || info.GoVersion == "" || info.OS == "" || info.Architecture == "" {
		t.Fatalf("missing development provenance: %+v", info)
	}
}

type brokenWriter struct{}

func TestAgentFailuresDoNotReflectPaths(t *testing.T) {
	for _, test := range []struct {
		args    []string
		message string
	}{
		{[]string{"agent", "catalog", "--socket", "synthetic-sensitive-input"}, "Local agent catalog failed.\n"},
		{[]string{"agent", "run", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input", "--secrets-fd", "3"}, "Agent configuration rejected.\n"},
		{[]string{"agent", "daemon", "--config", "synthetic-sensitive-input", "--socket", "synthetic-sensitive-input"}, "Local agent daemon failed.\n"},
		{[]string{"agent", "unlock", "--socket", "synthetic-sensitive-input", "--secrets-fd", "3"}, "Local agent unlock failed.\n"},
		{[]string{"agent", "lock", "--socket", "synthetic-sensitive-input"}, "Local agent lock failed.\n"},
		{[]string{"agent", "status", "--socket", "synthetic-sensitive-input"}, "Local agent status failed.\n"},
		{[]string{"agent", "exec", "--socket", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "1", "--endpoint", "synthetic-sensitive-input", "--", "/usr/bin/curl", "{socket}"}, "Local application launch failed.\n"},
	} {
		var out, errout bytes.Buffer
		if code := cli.Run(test.args, &out, &errout); code != 1 || out.Len() != 0 || errout.String() != test.message {
			t.Fatalf("agent failure: code=%d output=%q error=%q", code, out.String(), errout.String())
		}
	}
}

func TestEnrollmentConfigurationErrorsDoNotReflectPaths(t *testing.T) {
	for _, operation := range []string{"prepare", "redeem", "activate"} {
		var out, errout bytes.Buffer
		code := cli.Run([]string{"enroll", operation, "--config", "synthetic-sensitive-input", "--secrets-fd", "3"}, &out, &errout)
		if code != 1 || out.Len() != 0 || errout.String() != "Enrollment operation failed. Original state is preserved; do not replace the key to retry.\n" {
			t.Fatal("enrollment configuration failure reflected input or unexpected output")
		}
	}
}

func TestClientConfigurationErrorsDoNotReflectPaths(t *testing.T) {
	for _, args := range [][]string{
		{"client", "catalog", "--config", "synthetic-sensitive-input"},
		{"client", "connect", "--config", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "1"},
	} {
		var out, errout bytes.Buffer
		if code := cli.Run(args, &out, &errout); code != 1 || out.Len() != 0 || errout.String() != "Client configuration rejected.\n" {
			t.Fatal("client configuration failure must return a generic error without output")
		}
	}
}

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
