package cli_test

import (
	"bytes"
	"context"
	"testing"

	"portico.local/portico/internal/cli"
)

func TestSSHCommandsRejectAmbiguityWithoutReflectingInput(t *testing.T) {
	base := []string{"agent", "ssh", "--socket", "synthetic-sensitive-input", "--resource", "59d73719-4dc0-4d8c-898e-aa2f9466a89e", "--revision", "1", "--endpoint", "synthetic-sensitive-input", "--host", "synthetic-sensitive-input", "--user", "synthetic-sensitive-input", "--known-hosts", "synthetic-sensitive-input", "--identity", "synthetic-sensitive-input", "--"}
	for _, change := range []func([]string) []string{
		func(a []string) []string { return a[:18] },
		func(a []string) []string { a[7] = "01"; return a },
		func(a []string) []string { a[5] = "192.0.2.10:22"; return a },
		func(a []string) []string { a[14] = "--accept-new-host-key"; return a },
		func(a []string) []string { return []string{"agent", "fdpass", "synthetic-sensitive-input"} },
	} {
		args := change(append([]string(nil), base...))
		var out, errout bytes.Buffer
		if cli.Run(args, &out, &errout) != 2 || out.Len() != 0 || errout.String() != "Unsupported command or arguments. Use portico help.\n" {
			t.Fatal("malformed SSH command accepted or reflected input")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		args    []string
		message string
	}{
		{base, "Local SSH application failed.\n"},
		{[]string{"agent", "fdpass"}, "Local descriptor delivery failed.\n"},
	} {
		var out, errout bytes.Buffer
		if cli.RunContext(ctx, test.args, &out, &errout) != 1 || out.Len() != 0 || errout.String() != test.message {
			t.Fatal("canceled SSH command accepted or reflected input")
		}
	}
}
