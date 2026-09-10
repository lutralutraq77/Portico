package cli

import (
	"bytes"
	"context"
	"io"

	"portico.local/portico/internal/enrollment"
	"portico.local/portico/internal/wire"
)

type enrollmentSecrets struct {
	Passphrase       string `json:"passphrase"`
	Confirmation     string `json:"confirmation"`
	InvitationSecret string `json:"invitation_secret"`
}

func runEnrollment(ctx context.Context, operation, configuration string, stdout, stderr io.Writer) int {
	fail := func() int {
		_, _ = io.WriteString(stderr, "Enrollment operation failed. Original state is preserved; do not replace the key to retry.\n")
		return 1
	}
	config, err := enrollment.LoadConfig(configuration)
	if err != nil {
		return fail()
	}
	// A separate inherited read pipe carries secrets. Application stdin/stdout,
	// command arguments, environment variables and config files carry none.
	data, err := readEnrollmentSecrets(ctx, 3)
	if err != nil {
		return fail()
	}
	defer clear(data)
	var secrets enrollmentSecrets
	if wire.Decode(data, &secrets) != nil {
		return fail()
	}
	passphrase := []byte(secrets.Passphrase)
	defer clear(passphrase)
	if len(passphrase) < 16 || len(passphrase) > 1024 {
		return fail()
	}
	var message string
	switch operation {
	case "prepare":
		confirmation := []byte(secrets.Confirmation)
		defer clear(confirmation)
		if !bytes.Equal(passphrase, confirmation) || secrets.InvitationSecret != "" {
			return fail()
		}
		if ctx.Err() != nil || config.Prepare(passphrase) != nil {
			return fail()
		}
		message = "Encrypted enrollment attempt prepared.\n"
	case "redeem":
		if secrets.Confirmation != "" || len(secrets.InvitationSecret) != 43 || config.Redeem(ctx, passphrase, secrets.InvitationSecret) != nil {
			return fail()
		}
		message = "Enrollment certificate retained. Activation is required.\n"
	case "activate":
		if secrets.Confirmation != "" || secrets.InvitationSecret != "" || config.Activate(ctx, passphrase) != nil {
			return fail()
		}
		message = "Enrollment activation confirmed.\n"
	default:
		return fail()
	}
	if _, err := io.WriteString(stdout, message); err != nil {
		return 1
	}
	return 0
}
