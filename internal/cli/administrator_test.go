package cli_test

import (
	"bytes"
	"testing"

	"portico.local/portico/internal/cli"
)

func TestAdministratorRequiresExactSecretSource(t *testing.T) {
	for _, suffix := range [][]string{nil, {"--password", "synthetic-sensitive-input"}, {"--secrets-fd", "0"}, {"--secrets-fd", "03"}, {"--prompt", "--secrets-fd", "3"}, {"--prompt", "--no-sandbox"}} {
		args := append([]string{"admin", "open", "--config", "synthetic-sensitive-input"}, suffix...)
		var out, errout bytes.Buffer
		if code := cli.Run(args, &out, &errout); code != 2 || out.Len() != 0 || errout.String() != "Unsupported command or arguments. Use portico help.\n" {
			t.Fatal("administrator argument bypass or input reflection")
		}
	}
}

func TestAdministratorRejectsConfigBeforeReadingSecrets(t *testing.T) {
	for _, suffix := range [][]string{{"--prompt"}, {"--secrets-fd", "3"}} {
		args := append([]string{"admin", "open", "--config", "synthetic-sensitive-input"}, suffix...)
		var out, errout bytes.Buffer
		if code := cli.Run(args, &out, &errout); code != 1 || out.Len() != 0 || errout.String() != "Administrator session failed.\n" {
			t.Fatal("administrator failure exposed input or attempted secret input")
		}
	}
}
