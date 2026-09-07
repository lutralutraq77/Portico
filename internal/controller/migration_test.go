package controller

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentMigrationPreservesDataAndRollsBackOnAuditFailure(t *testing.T) {
	for _, rejectAudit := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve", true: "rollback"}[rejectAudit], func(t *testing.T) {
			dir := t.TempDir()
			db, e := sql.Open("sqlite", databaseURI(filepath.Join(dir, "controller.sqlite")))
			must(t, e)
			db.SetMaxOpenConns(1)
			_, e = db.Exec(schema)
			must(t, e)
			hash := sha256.Sum256([]byte(schema))
			digest := hex.EncodeToString(hash[:])
			_, e = db.Exec("INSERT INTO meta(singleton,schema_digest) VALUES(1,?)", digest)
			must(t, e)
			_, e = db.Exec("PRAGMA user_version=1; PRAGMA application_id=1347572803")
			must(t, e)
			legacy := &Store{db: db, now: time.Now}
			actor, user := NewID(), User{NewID(), "Existing owner", true}
			must(t, legacy.Update(ctx, actor, func(tx *Tx) error { return tx.AddUser(user) }))
			before := summary(t, legacy)
			if rejectAudit {
				_, e = db.Exec("CREATE TRIGGER reject_migration_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END;")
				must(t, e)
			}
			must(t, legacy.Close())
			s, e := Open(ctx, dir)
			if rejectAudit {
				if e == nil {
					_ = s.Close()
					t.Fatal("migration ignored audit failure")
				}
				db, e = sql.Open("sqlite", databaseURI(filepath.Join(dir, "controller.sqlite")))
				must(t, e)
				defer func() { _ = db.Close() }()
				var version, tables int
				var got string
				must(t, db.QueryRow("PRAGMA user_version").Scan(&version))
				must(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('enrollments','pki_bindings')").Scan(&tables))
				must(t, db.QueryRow("SELECT schema_digest FROM meta WHERE singleton=1").Scan(&got))
				if version != 1 || tables != 0 || got != digest {
					t.Fatal("partial migration escaped rollback")
				}
				must(t, verifyAudit(ctx, db))
				return
			}
			must(t, e)
			defer func() { _ = s.Close() }()
			after := summary(t, s)
			if after.Users != before.Users || after.Generation != before.Generation+1 || after.AuditSequence != before.AuditSequence+1 {
				t.Fatal("migration lost existing data/history")
			}
			var name string
			must(t, s.db.QueryRow("SELECT name FROM users WHERE id=?", user.ID).Scan(&name))
			if name != user.Name {
				t.Fatal("migration changed immutable owner")
			}
			must(t, verifyAudit(ctx, s.db))
		})
	}
}
