package agent

import (
	"context"
	"time"

	"portico.local/portico/internal/client"
	"portico.local/portico/internal/localfile"
	"portico.local/portico/internal/localipc"
	"portico.local/portico/internal/wire"
)

// RunLocked starts without decrypting or contacting infrastructure. The fixed
// local configuration is fully revalidated by LoadEncryptedConfig on unlock.
// Restart always creates a new locked manager, never an automatic unlock.
func RunLocked(ctx context.Context, path, configuration string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRejected
	}
	data, err := localfile.Read(configuration, wire.MaxBody, false)
	var config client.FileConfig
	if err != nil || wire.Decode(data, &config) != nil || config.Version != 2 || config.IdentityKeyFile != "" || config.IdentityCertificateFile != "" || config.EnrollmentConfigFile == "" {
		return ErrRejected
	}
	m, err := newManager(ctx, func(ctx context.Context, passphrase []byte) (resourceBackend, error) {
		config, err := client.LoadEncryptedConfig(ctx, configuration, passphrase)
		if err != nil || config == nil {
			return nil, ErrRejected
		}
		return config, nil
	})
	if err != nil {
		return ErrRejected
	}
	return runLocked(ctx, path, m)
}

func runLocked(ctx context.Context, path string, m *manager) (result error) {
	defer m.shutdown()
	l, err := localipc.Listen(path)
	if err != nil {
		return ErrRejected
	}
	defer func() {
		if l.Close() != nil {
			result = ErrRejected
		}
	}()
	s, err := newServer(m)
	if err != nil {
		return ErrRejected
	}
	defer s.stop()
	done := make(chan error, 1)
	go func() { done <- s.grpc.Serve(&limitedListener{Listener: l, server: s}) }()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop()
			<-done
			return nil
		case <-done:
			return ErrRejected
		case <-tick.C:
			if !m.healthy() {
				s.stop()
				<-done
				return ErrRejected
			}
		}
	}
}
