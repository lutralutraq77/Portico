package controller

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEncryptedRecoveryQuarantineTamperAndCheckpoint(t *testing.T) {
	f := enrollmentSeed(t)
	_ = f.issue(t)
	id, e := age.GenerateX25519Identity()
	must(t, e)
	path := filepath.Join(t.TempDir(), "recovery.age")
	anchor, e := f.f.s.ExportRecovery(ctx, path, id.Recipient().String())
	must(t, e)
	ciphertext, e := os.ReadFile(path)
	must(t, e)
	if bytes.Contains(ciphertext, []byte("SQLite format")) || !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1")) {
		t.Fatal("backup not age encrypted")
	}
	dir := t.TempDir()
	destination := filepath.Join(dir, "controller.sqlite")
	must(t, RestoreRecovery(ctx, path, destination, id.String(), anchor))
	if s, e := Open(ctx, dir); e != ErrQuarantine {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("restored authority escaped quarantine")
	}
	if e := RestoreRecovery(ctx, path, destination, id.String(), anchor); e == nil {
		t.Fatal("restore overwrote existing file")
	}
	// Anyone holding the public recipient can construct a fresh, valid age
	// archive. Even re-encryption of identical content needs a trusted new anchor.
	plain, e := age.Decrypt(bytes.NewReader(ciphertext), id)
	must(t, e)
	var forged bytes.Buffer
	encrypt, e := age.Encrypt(&forged, id.Recipient())
	must(t, e)
	_, e = io.Copy(encrypt, plain)
	must(t, e)
	must(t, encrypt.Close())
	forgedPath := filepath.Join(t.TempDir(), "forged.age")
	must(t, os.WriteFile(forgedPath, forged.Bytes(), 0600))
	if e = RestoreRecovery(ctx, forgedPath, filepath.Join(t.TempDir(), "controller.sqlite"), id.String(), anchor); e == nil {
		t.Fatal("public-recipient encryption bypassed independent anchor")
	}
	for _, name := range []string{"wrong_key", "tampered", "truncated", "appended", "old_checkpoint", "wrong_history"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(ciphertext)
			identity := id.String()
			cp := anchor
			switch name {
			case "wrong_key":
				other, e := age.GenerateX25519Identity()
				must(t, e)
				identity = other.String()
			case "tampered":
				data[len(data)-20] ^= 1
			case "truncated":
				data = data[:len(data)-1]
			case "appended":
				data = append(data, 1)
			case "old_checkpoint":
				cp.Checkpoint.Sequence += 100
			case "wrong_history":
				cp.Checkpoint.Hash = strings.Repeat("f", 64)
			}
			source := filepath.Join(t.TempDir(), "bad.age")
			must(t, os.WriteFile(source, data, 0600))
			dir := t.TempDir()
			dest := filepath.Join(dir, "controller.sqlite")
			if e := RestoreRecovery(ctx, source, dest, identity, cp); e == nil {
				t.Fatal("invalid archive accepted")
			}
			entries, e := os.ReadDir(dir)
			must(t, e)
			if len(entries) != 0 {
				t.Fatal("failed restore left plaintext or published output")
			}
		})
	}
}
