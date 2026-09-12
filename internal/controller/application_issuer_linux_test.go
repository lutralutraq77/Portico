//go:build linux

package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	issuerclient "portico.local/portico/internal/issuer"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
)

// The production restricted issuer runs in a separate process. All custody
// material here is generated inside the disposable guest and is fixture-only.
func applicationIssuer(t *testing.T, f *enrollmentFixture) *issuerclient.Client {
	t.Helper()
	requireArchApplicationGuest(t)
	dir, err := os.MkdirTemp("/", "portico-application-issuer-")
	must(t, err)
	t.Cleanup(func() { must(t, os.RemoveAll(dir)) })
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, data, 0600))
		return path
	}
	certificate := func(name string, der []byte) string {
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	keyFile := func(name string, key any) string {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		must(t, err)
		defer clear(der)
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	root, rootKey := testfixture.Root(t)
	server := testfixture.TLSIdentity(t, root, rootKey, true)
	controller := testfixture.TLSIdentity(t, root, rootKey, false)
	provisionerKey := testfixture.Key(t)
	public := jose.JSONWebKey{Key: &provisionerKey.PublicKey, KeyID: NewID(), Algorithm: "ES256", Use: "sig"}
	publicJSON, err := json.Marshal(public)
	must(t, err)
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	address := reservation.Addr().String()
	must(t, reservation.Close())
	endpoint := "https://localhost:" + strings.Split(address, ":")[1]
	password := []byte(pki.Hash([]byte(NewID())))
	defer clear(password)
	passwordFile := write("issuer-password", password)
	plainKey := keyFile("issuer-plain.pem", f.caKey)
	encryptedKey := filepath.Join(dir, "issuer-encrypted.pem")
	// OpenSSL from the pinned guest image creates a PKCS8 fixture envelope.
	// No crypto implementation or new production dependency is introduced.
	encryptionContext, encryptionCancel := context.WithTimeout(ctx, 10*time.Second)
	defer encryptionCancel()
	encrypt := exec.CommandContext(encryptionContext, "/usr/bin/openssl", "pkcs8", "-topk8", "-in", plainKey, "-out", encryptedKey, "-passout", "file:"+passwordFile)
	must(t, encrypt.Run())
	must(t, os.Chmod(encryptedKey, 0600))
	must(t, os.Remove(plainKey))
	config := map[string]any{
		"ListenAddress": address, "Endpoint": endpoint, "Provisioner": "portico-application-fixture", "KeyID": public.KeyID,
		"DatabasePath": filepath.Join(dir, "issuer.db"), "DeploymentID": f.config.DeploymentID, "IssuerID": f.config.IssuerID, "Profile": f.config.Profile,
		"RootCertificateFile": certificate("root.pem", f.config.RootDER), "IssuerCertificateFile": certificate("issuer.pem", f.config.IssuerDER),
		"IssuerKeyFile": encryptedKey, "IssuerPasswordFile": passwordFile, "ProvisionerPublicKeyFile": write("provisioner.json", publicJSON),
		"ServerCertificateFile": certificate("server.pem", server.Certificate[0]), "ServerKeyFile": keyFile("server-key.pem", server.PrivateKey),
		"ControllerRootFile": certificate("controller-root.pem", root.Raw), "ControllerSPKI": pki.Hash(controller.Leaf.RawSubjectPublicKeyInfo),
	}
	configJSON, err := json.Marshal(config)
	must(t, err)
	runContext, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(runContext, "/portico-issuer", "serve", "--config", write("issuer.json", configJSON))
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	command.WaitDelay = 5 * time.Second
	started := time.Now()
	must(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("restricted issuer process failed: %v", err)
			}
		case <-time.After(6 * time.Second):
			cancel()
			<-done
			t.Error("restricted issuer did not stop within its bound")
		}
		cancel()
		if logs.Len() != 0 {
			t.Error("restricted issuer unexpectedly emitted diagnostic output")
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(root)
	// Startup includes loading the separate Go/Smallstep process under TCG.
	// This readiness allowance is unrelated to issuance or resource deadlines.
	deadline := time.Now().Add(90 * time.Second)
	for {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{controller}})
		if err == nil {
			must(t, c.Close())
			t.Logf("restricted issuer authenticated readiness after %s", time.Since(started))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restricted issuer did not become ready with authenticated TLS: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	client, err := issuerclient.New(issuerclient.Config{Endpoint: endpoint, Provisioner: "portico-application-fixture", KeyID: public.KeyID, ProvisionerKey: provisionerKey, ServerRootDER: root.Raw, ServerSPKI: pki.Hash(server.Leaf.RawSubjectPublicKeyInfo), ControllerIdentity: controller, Trust: f.trust})
	must(t, err)
	return client
}
