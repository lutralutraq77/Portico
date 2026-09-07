package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const MaxRecoveryBytes int64 = 64 << 20

// Keep this anchor independently from the archive, through a trusted local
// channel. Age recipient encryption does not authenticate the archive's sender.
type RecoveryAnchor struct {
	CiphertextSHA256 string
	Checkpoint       Checkpoint
}

func recoveryPath(path string) bool { return filepath.IsAbs(path) && !strings.HasPrefix(path, "\\\\") }

// ExportRecovery encrypts a consistent quarantined snapshot to an offline age
// recipient. It is a trusted local primitive; an admin transport must authorize
// export separately. The decryption identity never enters this process.
// The parent directory must be owner-only (including Windows ACLs). Temporary
// plaintext is removed on return; interrupted exports require local cleanup.
func (s *Store) ExportRecovery(ctx context.Context, destination, recipient string) (RecoveryAnchor, error) {
	var anchor RecoveryAnchor
	if !recoveryPath(destination) {
		return anchor, ErrInvalid
	}
	r, e := age.ParseX25519Recipient(recipient)
	if e != nil {
		return anchor, ErrInvalid
	}
	plain := filepath.Join(filepath.Dir(destination), ".portico-recovery-"+NewID()+".sqlite")
	defer func() { _ = os.Remove(plain) }()
	if e = s.Snapshot(ctx, plain); e != nil {
		return anchor, e
	}
	db, e := sql.Open("sqlite", databaseURI(plain))
	if e != nil {
		return anchor, ErrStorage
	}
	e = db.QueryRowContext(ctx, "SELECT audit_sequence,audit_hash FROM meta WHERE singleton=1").Scan(&anchor.Checkpoint.Sequence, &anchor.Checkpoint.Hash)
	closeErr := db.Close()
	if e != nil || closeErr != nil {
		return RecoveryAnchor{}, ErrStorage
	}
	f, e := os.Open(plain)
	if e != nil {
		return RecoveryAnchor{}, ErrStorage
	}
	defer func() { _ = f.Close() }()
	stat, e := f.Stat()
	if e != nil || stat.Size() > MaxRecoveryBytes {
		return RecoveryAnchor{}, ErrStorage
	}
	hash := sha256.New()
	e = publishRecovery(destination, func(out *os.File) error {
		w, e := age.Encrypt(io.MultiWriter(out, hash), r)
		if e != nil {
			return ErrStorage
		}
		if _, e = io.Copy(w, &contextReader{ctx: ctx, r: f}); e != nil {
			return ErrStorage
		}
		if e = w.Close(); e != nil {
			return ErrStorage
		}
		return nil
	})
	if e != nil {
		return RecoveryAnchor{}, e
	}
	anchor.CiphertextSHA256 = hex.EncodeToString(hash.Sum(nil))
	return anchor, nil
}

// RestoreRecovery authenticates the entire archive before parsing or publishing
// its database. The output remains quarantined and all restored credentials are
// revoked. No call re-enables authority. The independently retained anchor binds
// the exact encrypted bytes and their audit checkpoint. It cannot establish
// freshness beyond that archive; current revocations still require reconciliation.
func RestoreRecovery(ctx context.Context, source, destination, identity string, anchor RecoveryAnchor) error {
	checkpoint := anchor.Checkpoint
	if !recoveryPath(source) || !recoveryPath(destination) || !digest(anchor.CiphertextSHA256) || checkpoint.Sequence <= 0 || !digest(checkpoint.Hash) {
		return ErrInvalid
	}
	id, e := age.ParseX25519Identity(identity)
	if e != nil {
		return ErrInvalid
	}
	f, e := os.Open(source)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = f.Close() }()
	stat, e := f.Stat()
	if e != nil || !stat.Mode().IsRegular() || stat.Size() > MaxRecoveryBytes+(1<<20) {
		return ErrInvalid
	}
	hash := sha256.New()
	r, e := age.Decrypt(io.TeeReader(&contextReader{ctx: ctx, r: f}, hash), id)
	if e != nil {
		return ErrDenied
	}
	return publishRecovery(destination, func(out *os.File) error {
		n, e := io.Copy(out, io.LimitReader(r, MaxRecoveryBytes+1))
		if e != nil || n > MaxRecoveryBytes {
			return ErrDenied
		}
		if hex.EncodeToString(hash.Sum(nil)) != anchor.CiphertextSHA256 {
			return ErrDenied
		}
		if e = out.Sync(); e != nil {
			return ErrStorage
		}
		if e = out.Close(); e != nil {
			return ErrStorage
		}
		return validateRecovery(ctx, out.Name(), checkpoint)
	})
}

func publishRecovery(destination string, write func(*os.File) error) error {
	path := filepath.Join(filepath.Dir(destination), ".portico-publish-"+NewID())
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = f.Close(); _ = os.Remove(path) }()
	if e = write(f); e != nil {
		return e
	}
	// The restore validator closes and edits the temporary file. Reopen it to
	// synchronize the final bytes before exclusive publication in either path.
	_ = f.Close()
	syncFile, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		return ErrStorage
	}
	e = syncFile.Sync()
	closeErr := syncFile.Close()
	if e != nil || closeErr != nil {
		return ErrStorage
	}
	if e = os.Link(path, destination); e != nil {
		return ErrStorage
	}
	return nil
}

func validateRecovery(ctx context.Context, path string, checkpoint Checkpoint) error {
	db, e := sql.Open("sqlite", databaseURI(path))
	if e != nil {
		return ErrIntegrity
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	var app, version, quarantine int
	var check, schemaHash string
	if db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app) != nil || app != applicationID || db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version) != nil || version != schemaVersion || db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" || db.QueryRowContext(ctx, "SELECT quarantined,schema_digest FROM meta WHERE singleton=1").Scan(&quarantine, &schemaHash) != nil || quarantine != 1 || schemaHash != currentSchemaDigest() {
		return ErrIntegrity
	}
	if e = verifyAudit(ctx, db); e != nil {
		return e
	}
	if checkpoint.Sequence > 0 {
		var hash string
		if db.QueryRowContext(ctx, "SELECT hash FROM audit_events WHERE sequence=?", checkpoint.Sequence).Scan(&hash) != nil || hash != checkpoint.Hash {
			return ErrIntegrity
		}
	}
	rows, e := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return ErrIntegrity
	}
	bad := rows.Next()
	rowErr := rows.Err()
	_ = rows.Close()
	if bad || rowErr != nil {
		return ErrIntegrity
	}
	var live int
	if db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM sessions WHERE state='requested')+(SELECT count(*) FROM enrollments WHERE state<>'revoked')+(SELECT count(*) FROM certificates WHERE revoked=0)+(SELECT count(*) FROM admin_devices WHERE enabled=1)+(SELECT count(*) FROM admin_factors WHERE enabled=1)+(SELECT count(*) FROM admin_ceremonies)+(SELECT count(*) FROM authorized_sessions WHERE state<>'closed')+(SELECT count(*) FROM policy_previews)").Scan(&live) != nil || live != 0 {
		return ErrQuarantine
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}
