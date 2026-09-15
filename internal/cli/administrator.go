package cli

import (
	"context"
	"io"
	"unicode/utf8"

	"portico.local/portico/internal/adminapp"
	"portico.local/portico/internal/wire"
)

const adminUsage = "Administrator development command: portico admin open --config /absolute/path/admin.json (--secrets-fd 3 | --prompt)\nRequires a protected Linux installation, an existing enrolled administrator certificate and encrypted key.\n"

func runAdministrator(ctx context.Context, path string, source secretSource, stderr io.Writer) int {
	fail := func() int { _, _ = io.WriteString(stderr, "Administrator session failed.\n"); return 1 }
	config, err := adminapp.Load(path)
	if err != nil {
		return fail()
	}
	data, err := readCommandSecrets(ctx, "administrator", source)
	defer clear(data)
	var secrets struct {
		Passphrase string `json:"passphrase"`
	}
	if err != nil || !utf8.Valid(data) || wire.Decode(data, &secrets) != nil {
		return fail()
	}
	passphrase := []byte(secrets.Passphrase)
	clear(data)
	secrets.Passphrase = ""
	defer clear(passphrase)
	if config.Run(ctx, passphrase) != nil {
		return fail()
	}
	return 0
}
