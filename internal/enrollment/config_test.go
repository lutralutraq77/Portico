package enrollment

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func TestEnrollmentConfigurationTrustAndSecretBoundary(t *testing.T) {
	f, _ := stateFixture(t)
	file := FileConfig{
		Version: 1, DeploymentID: f.config.Trust.DeploymentID(), Profile: pki.Device,
		Issuer:      identityfile.TrustFiles{IssuerID: f.config.Trust.IssuerID(), RootCertificateFile: "root", IssuerCertificateFile: "issuer"},
		PrincipalID: f.config.PrincipalID, InvitationID: f.request.InvitationID, NotAfter: f.config.NotAfter.UTC().Format(time.RFC3339), StateFile: "/private/attempt.age",
		Redemption: identityfile.EndpointFiles{URL: f.config.Redemption.URL, RootCertificateFile: "root", SPKI: f.config.Redemption.ServerSPKI},
		Activation: identityfile.EndpointFiles{URL: f.config.Activation.URL, RootCertificateFile: "root", SPKI: f.config.Activation.ServerSPKI}, OperationTimeoutMillis: 5000,
	}
	encode := func(c FileConfig) []byte { b, err := json.Marshal(c); testfixture.Must(t, err); return b }
	var config []byte
	read := func(path string, max int64, secret bool) ([]byte, error) {
		if secret {
			t.Error("public configuration requested a secret file")
		}
		var b []byte
		switch path {
		case "config":
			b = config
		case "root":
			b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw})
		case "issuer":
			b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw})
		default:
			return nil, errors.New("fixture rejected")
		}
		if int64(len(b)) > max {
			t.Fatal("loader exceeded declared file bound")
		}
		return bytes.Clone(b), nil
	}
	config = encode(file)
	loaded, err := loadConfig("config", read)
	testfixture.Must(t, err)
	if loaded.stateFile != file.StateFile || loaded.invitation != file.InvitationID || loaded.client.Trust.RootFingerprint() != f.config.Trust.RootFingerprint() {
		t.Fatal("approved configuration changed")
	}
	for _, tc := range []struct {
		name   string
		change func(*FileConfig)
	}{
		{"version", func(c *FileConfig) { c.Version++ }},
		{"administrator", func(c *FileConfig) { c.Profile = pki.Administrator }},
		{"deployment", func(c *FileConfig) { c.DeploymentID = "invalid" }},
		{"invitation", func(c *FileConfig) { c.InvitationID = "invalid" }},
		{"principal", func(c *FileConfig) { c.PrincipalID = "invalid" }},
		{"fractional_deadline", func(c *FileConfig) { c.NotAfter = f.config.NotAfter.Add(time.Nanosecond).Format(time.RFC3339Nano) }},
		{"non_utc_deadline", func(c *FileConfig) { c.NotAfter = strings.TrimSuffix(c.NotAfter, "Z") + "+00:00" }},
		{"expired", func(c *FileConfig) { c.NotAfter = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339) }},
		{"relative_state", func(c *FileConfig) { c.StateFile = "relative" }},
		{"state_alias", func(c *FileConfig) { c.StateFile = "/private/../private/attempt.age" }},
		{"state_nul", func(c *FileConfig) { c.StateFile = "/private/\x00state" }},
		{"state_too_long", func(c *FileConfig) { c.StateFile = "/" + strings.Repeat("a", 4090) }},
		{"root", func(c *FileConfig) { c.Issuer.RootCertificateFile = "absent" }},
		{"redemption_pin", func(c *FileConfig) { c.Redemption.SPKI = "invalid" }},
		{"activation_root", func(c *FileConfig) { c.Activation.RootCertificateFile = "absent" }},
		{"external_redemption", func(c *FileConfig) { c.Redemption.URL = "https://example.test:443" }},
		{"same_endpoint", func(c *FileConfig) { c.Activation.URL = c.Redemption.URL }},
		{"timeout", func(c *FileConfig) { c.OperationTimeoutMillis = 5001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := file
			tc.change(&changed)
			config = encode(changed)
			if c, err := loadConfig("config", read); c != nil || err != ErrRejected {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for _, extra := range []string{`,"secret":"must-not-be-in-config"}`, `,"private_key":"must-not-be-in-config"}`, `,"VERSION":1}`, `}{}`} {
		config = append(bytes.TrimSuffix(encode(file), []byte("}")), []byte(extra)...)
		if c, err := loadConfig("config", read); c != nil || err != ErrRejected {
			t.Fatal("secret or ambiguous configuration accepted")
		}
	}
}
