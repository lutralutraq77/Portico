package cli

import (
	"context"
	"unicode/utf8"

	"portico.local/portico/internal/client"
	"portico.local/portico/internal/wire"
)

func loadClientConfiguration(ctx context.Context, path string, encrypted bool) (*client.Configuration, error) {
	if !encrypted {
		return client.LoadConfig(path)
	}
	data, err := readEnrollmentSecrets(ctx, 3)
	if err != nil {
		return nil, client.ErrConfiguration
	}
	defer clear(data)
	var secrets struct {
		Passphrase string `json:"passphrase"`
	}
	if !utf8.Valid(data) || wire.Decode(data, &secrets) != nil {
		return nil, client.ErrConfiguration
	}
	passphrase := []byte(secrets.Passphrase)
	defer clear(passphrase)
	return client.LoadEncryptedConfig(ctx, path, passphrase)
}
