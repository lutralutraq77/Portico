package cli

import (
	"context"
	"unicode/utf8"

	"portico.local/portico/internal/client"
	"portico.local/portico/internal/wire"
)

func loadClientConfiguration(ctx context.Context, path string, source secretSource) (*client.Configuration, error) {
	if source == noSecretSource {
		return client.LoadConfig(path)
	}
	passphrase, err := readClientPassphrase(ctx, source)
	if err != nil {
		return nil, client.ErrConfiguration
	}
	defer clear(passphrase)
	return client.LoadEncryptedConfig(ctx, path, passphrase)
}

func readClientPassphrase(ctx context.Context, source secretSource) ([]byte, error) {
	data, err := readCommandSecrets(ctx, "client", source)
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
	return passphrase, nil
}
