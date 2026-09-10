//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"portico.local/portico/internal/identityfile"
	"portico.local/portico/internal/pki"
	"portico.local/portico/internal/testfixture"
	"portico.local/portico/internal/wire"
)

func TestGuestEncryptedAttemptSurvivesLostResponses(t *testing.T) {
	if os.Getenv("PORTICO_ISOLATED_VM") != "1" {
		t.Skip("requires disposable guest root")
	}
	marker, err := os.ReadFile("/portico-isolated-fixture")
	if err != nil || string(marker) != "192.0.2.10\n" || os.Geteuid() != 0 {
		t.Fatal("missing disposable guest guard")
	}
	directory, err := os.MkdirTemp("/", "portico-enrollment-")
	testfixture.Must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "attempt.age")
	passphrase := []byte("isolated guest fixture passphrase")
	defer clear(passphrase)
	f := newClientFixture(t)
	var lock sync.Mutex
	var savedRequest RedeemRequest
	var issued []byte
	var redemptions, signatures, activations int
	f.config.Redemption = f.serve(t, func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		redemptions++
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		var request RedeemRequest
		if err != nil || wire.Decode(body, &request) != nil || !request.Valid() || request.InvitationID != f.request.InvitationID || request.Secret != f.request.Secret || r.URL.Path != RedeemPath || len(r.TLS.PeerCertificates) != 0 {
			t.Error("invalid redemption")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		csr, err := pki.ParseCSR(request.CSR)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if issued == nil {
			savedRequest = request
			public := csr.PublicKey.(*ecdsa.PublicKey)
			issued = f.leaf(t, f.config.PrincipalID, &ecdsa.PrivateKey{PublicKey: *public}, f.config.NotAfter)
			signatures++
		} else {
			previous, err := pki.ParseCSR(savedRequest.CSR)
			if err != nil || savedRequest.AttemptID != request.AttemptID || !bytes.Equal(previous.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
				t.Error("retry changed the original attempt or key")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if redemptions == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close() // Issued once; public response was lost.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CertificateResponse{Version: Version, InvitationID: request.InvitationID, AttemptID: request.AttemptID, CertificateDER: issued})
	})
	f.config.Activation = f.serve(t, func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		if r.URL.Path != ActivatePath || len(r.TLS.PeerCertificates) < 1 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, issued) {
			t.Error("activation did not prove the retained key on real TLS")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if _, err := f.config.Trust.Verify(r.TLS.PeerCertificates[0].Raw, f.config.PrincipalID, time.Now()); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		activations++
		if activations == 1 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close() // Activation happened, but its response was lost.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Activated{Version: Version, InvitationID: f.request.InvitationID})
	})
	c, err := New(f.config)
	testfixture.Must(t, err)
	defer c.Close()
	rootPath, issuerPath := filepath.Join(directory, "root.pem"), filepath.Join(directory, "issuer.pem")
	testfixture.Must(t, os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}), 0600))
	testfixture.Must(t, os.WriteFile(issuerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600))
	configuration := FileConfig{Version: 1, DeploymentID: f.config.Trust.DeploymentID(), Profile: pki.Device,
		Issuer:      identityfile.TrustFiles{IssuerID: f.config.Trust.IssuerID(), RootCertificateFile: rootPath, IssuerCertificateFile: issuerPath},
		PrincipalID: f.config.PrincipalID, InvitationID: f.request.InvitationID, NotAfter: f.config.NotAfter.UTC().Format(time.RFC3339), StateFile: path,
		Redemption: identityfile.EndpointFiles{URL: f.config.Redemption.URL, RootCertificateFile: rootPath, SPKI: f.config.Redemption.ServerSPKI},
		Activation: identityfile.EndpointFiles{URL: f.config.Activation.URL, RootCertificateFile: rootPath, SPKI: f.config.Activation.ServerSPKI}, OperationTimeoutMillis: 5000}
	configurationBytes, err := json.Marshal(configuration)
	testfixture.Must(t, err)
	configurationPath := filepath.Join(directory, "enrollment.json")
	testfixture.Must(t, os.WriteFile(configurationPath, configurationBytes, 0600))
	runCommand := func(operation string, success bool) {
		t.Helper()
		secrets := map[string]string{"passphrase": string(passphrase)}
		if operation == "prepare" {
			secrets["confirmation"] = string(passphrase)
		}
		if operation == "redeem" {
			secrets["invitation_secret"] = f.request.Secret
		}
		data, err := json.Marshal(secrets)
		testfixture.Must(t, err)
		defer clear(data)
		input, output, err := os.Pipe()
		testfixture.Must(t, err)
		defer input.Close()
		defer output.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/portico", "enroll", operation, "--config", configurationPath, "--secrets-fd", "3")
		command.ExtraFiles = []*os.File{input}
		command.Stdin = strings.NewReader("application stdin must never be read as an enrollment secret")
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		testfixture.Must(t, command.Start())
		_ = input.Close()
		_, writeErr := output.Write(data)
		_ = output.Close()
		err = command.Wait()
		if writeErr != nil || ctx.Err() != nil || (err == nil) != success {
			t.Fatalf("%s command success=%v: %v; %s", operation, success, err, stderr.String())
		}
		if bytes.Contains(stdout.Bytes(), passphrase) || bytes.Contains(stderr.Bytes(), passphrase) || strings.Contains(stdout.String()+stderr.String(), f.request.Secret) {
			t.Fatal("command leaked a secret")
		}
		if success {
			messages := map[string]string{"prepare": "Encrypted enrollment attempt prepared.\n", "redeem": "Enrollment certificate retained. Activation is required.\n", "activate": "Enrollment activation confirmed.\n"}
			if stdout.String() != messages[operation] || stderr.Len() != 0 {
				t.Fatal("unexpected successful command output")
			}
		} else if stdout.Len() != 0 || stderr.String() != "Enrollment operation failed. Original state is preserved; do not replace the key to retry.\n" {
			t.Fatal("unexpected failed command output")
		}
	}
	runCommand("prepare", true)
	a, err := OpenAttempt(path, f.config, f.request.InvitationID, passphrase)
	testfixture.Must(t, err)
	onDisk, err := os.ReadFile(path)
	testfixture.Must(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(a.key)
	testfixture.Must(t, err)
	defer clear(privateDER)
	if bytes.Contains(onDisk, privateDER) || bytes.Contains(onDisk, []byte(f.request.Secret)) || bytes.Contains(onDisk, []byte(a.id)) {
		t.Fatal("private enrollment state persisted in plaintext")
	}
	originalID, originalPublic := a.id, a.key.Public()
	runCommand("prepare", false)
	runCommand("redeem", false)
	if _, err := os.Stat(path + ".certificate"); !os.IsNotExist(err) {
		t.Fatal("retained unreceived certificate")
	}
	a = nil
	a, err = OpenAttempt(path, f.config, f.request.InvitationID, passphrase)
	testfixture.Must(t, err)
	if a.id != originalID || !a.key.PublicKey.Equal(originalPublic) {
		t.Fatal("reopened state changed key/attempt")
	}
	runCommand("redeem", true)
	runCommand("redeem", true)
	runCommand("activate", false)
	a = nil
	a, err = OpenAttempt(path, f.config, f.request.InvitationID, passphrase)
	testfixture.Must(t, err)
	runCommand("activate", true)
	identity, err := a.Certificate(c)
	testfixture.Must(t, err)
	lock.Lock()
	if signatures != 1 || redemptions != 3 || activations != 2 || !bytes.Equal(identity.Certificate[0], issued) {
		t.Error("recovery changed issuance or activation semantics")
	}
	lock.Unlock()
	current, err := os.ReadFile(path)
	testfixture.Must(t, err)
	if !bytes.Equal(current, onDisk) {
		t.Fatal("retry rewrote encrypted attempt")
	}
	certificatePath := path + ".certificate"
	certificateData, err := os.ReadFile(certificatePath)
	testfixture.Must(t, err)
	var record certificateRecord
	testfixture.Must(t, wire.Decode(certificateData, &record))
	record.AttemptID = f.request.AttemptID // Another attempt, same invitation.
	changed, err := json.Marshal(record)
	testfixture.Must(t, err)
	testfixture.Must(t, os.WriteFile(certificatePath, changed, 0600))
	if _, err := a.Certificate(c); err != ErrRejected {
		t.Fatal("substituted certificate record accepted")
	}
	runCommand("activate", false)
	lock.Lock()
	if activations != 2 {
		t.Error("invalid local state caused network activation")
	}
	lock.Unlock()
	entries, err := os.ReadDir(directory)
	testfixture.Must(t, err)
	if len(entries) != 5 {
		t.Fatal("unexpected private state files")
	}
}
