package service

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/pemutil"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

func writeLabConfig(t *testing.T, l *lab) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		testfixture.Must(t, os.WriteFile(path, b, 0600))
		return path
	}
	certFile := func(name string, der []byte) string {
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	password := make([]byte, 32)
	_, e := rand.Read(password)
	testfixture.Must(t, e)
	// Hex password avoids whitespace normalization ambiguity in the fixture.
	password = []byte(pki.Hash(password))
	encrypted, e := pemutil.Serialize(l.config.IssuerSigner, pemutil.WithPKCS8(true), pemutil.WithPassword(password))
	testfixture.Must(t, e)
	serverKey, e := x509.MarshalPKCS8PrivateKey(l.config.ServerIdentity.PrivateKey)
	testfixture.Must(t, e)
	public, e := json.Marshal(l.config.ProvisionerPublicKey)
	testfixture.Must(t, e)
	c := FileConfig{ListenAddress: strings.Replace(strings.TrimPrefix(l.config.Endpoint, "https://"), "localhost", "127.0.0.1", 1), Endpoint: l.config.Endpoint, Provisioner: l.config.Provisioner, KeyID: l.config.KeyID, DatabasePath: l.config.DatabasePath, DeploymentID: l.config.TrustConfig.DeploymentID, IssuerID: l.config.TrustConfig.IssuerID, Profile: l.config.TrustConfig.Profile, RootCertificateFile: certFile("root.pem", l.config.TrustConfig.RootDER), IssuerCertificateFile: certFile("issuer.pem", l.config.TrustConfig.IssuerDER), IssuerKeyFile: write("issuer-encrypted.pem", pem.EncodeToMemory(encrypted)), IssuerPasswordFile: write("issuer-password.txt", password), ProvisionerPublicKeyFile: write("provisioner-public.json", public), ServerCertificateFile: certFile("server.pem", l.config.ServerIdentity.Certificate[0]), ServerKeyFile: write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey})), ControllerRootFile: certFile("controller-root.pem", l.config.ControllerRootDER), ControllerSPKI: l.config.ControllerSPKI}
	b, e := json.Marshal(c)
	testfixture.Must(t, e)
	return write("config.json", b)
}
func TestIssuerProcessFixture(t *testing.T) {
	path := os.Getenv("PORTICO_ISSUER_PROCESS_FIXTURE")
	if path == "" {
		t.Skip("subprocess helper")
	}
	config, address, e := LoadConfig(path)
	testfixture.Must(t, e)
	s, e := New(config)
	testfixture.Must(t, e)
	l, e := net.Listen("tcp4", address)
	testfixture.Must(t, e)
	_, e = os.Stdout.WriteString("PORTICO_ISSUER_READY\n")
	testfixture.Must(t, e)
	_ = s.Serve(l)
}
func TestEncryptedConfigAndSeparateIssuerProcess(t *testing.T) {
	l := newLab(t, pki.Device)
	path := writeLabConfig(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	testfixture.Must(t, l.s.Close(ctx))
	config, address, e := LoadConfig(path)
	testfixture.Must(t, e)
	if config.TrustConfig.Profile != pki.Device || !strings.HasPrefix(address, "127.0.0.1:") {
		t.Fatal("configuration changed identity or listener")
	}
	executable, e := os.Executable()
	testfixture.Must(t, e)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestIssuerProcessFixture$")
	cmd.Env = append(os.Environ(), "PORTICO_ISSUER_PROCESS_FIXTURE="+path)
	stdout, e := cmd.StdoutPipe()
	testfixture.Must(t, e)
	cmd.Stderr = io.Discard
	testfixture.Must(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make([]byte, len("PORTICO_ISSUER_READY\n"))
	_, e = io.ReadFull(stdout, ready)
	testfixture.Must(t, e)
	if string(ready) != "PORTICO_ISSUER_READY\n" {
		t.Fatal("child did not start restricted issuer")
	}
	der, e := l.client.Issue(ctx, l.request)
	testfixture.Must(t, e)
	_, e = l.trust.Verify(der, l.request.PrincipalID, time.Now())
	testfixture.Must(t, e)
	if _, e = l.client.Issue(ctx, l.request); e == nil {
		t.Fatal("separate issuer process replayed token")
	}
}

func TestConfigRejectsUnsafeListenerAndKeyFiles(t *testing.T) {
	l := newLab(t, pki.Device)
	path := writeLabConfig(t, l)
	data, e := os.ReadFile(path)
	testfixture.Must(t, e)
	var original FileConfig
	testfixture.Must(t, json.Unmarshal(data, &original))
	for _, name := range []string{"public_listener", "mismatched_port", "relative_file", "unknown_field", "plaintext_key", "trailing_key", "blank_password"} {
		t.Run(name, func(t *testing.T) {
			c := original
			dir := t.TempDir()
			write := func(name string, b []byte) string {
				p := filepath.Join(dir, name)
				testfixture.Must(t, os.WriteFile(p, b, 0600))
				return p
			}
			switch name {
			case "public_listener":
				c.ListenAddress = "0.0.0.0:443"
			case "mismatched_port":
				c.ListenAddress = "127.0.0.1:1"
			case "relative_file":
				c.IssuerKeyFile = "relative.pem"
			case "plaintext_key":
				der, e := x509.MarshalPKCS8PrivateKey(l.config.IssuerSigner)
				testfixture.Must(t, e)
				c.IssuerKeyFile = write("plain.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			case "trailing_key":
				b, e := os.ReadFile(c.IssuerKeyFile)
				testfixture.Must(t, e)
				c.IssuerKeyFile = write("extra.pem", append(b, b...))
			case "blank_password":
				c.IssuerPasswordFile = write("blank.txt", []byte(strings.Repeat(" ", 32)))
			}
			b, e := json.Marshal(c)
			testfixture.Must(t, e)
			if name == "unknown_field" {
				var object map[string]any
				testfixture.Must(t, json.Unmarshal(b, &object))
				object["allowInsecure"] = true
				b, e = json.Marshal(object)
				testfixture.Must(t, e)
			}
			if _, _, e = LoadConfig(write("config.json", b)); e == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
