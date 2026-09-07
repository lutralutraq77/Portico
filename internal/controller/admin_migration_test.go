package controller

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionTwoMigrationAndAuditFailureRollback(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrate", true: "rollback"}[reject], func(t *testing.T) {
			dir := t.TempDir()
			db, e := sql.Open("sqlite", databaseURI(filepath.Join(dir, "controller.sqlite")))
			must(t, e)
			_, e = db.Exec(schema + enrollmentSchema)
			must(t, e)
			hash := sha256.Sum256([]byte(schema + enrollmentSchema))
			old := hex.EncodeToString(hash[:])
			_, e = db.Exec("INSERT INTO meta(singleton,schema_digest) VALUES(1,?)", old)
			must(t, e)
			_, e = db.Exec("PRAGMA user_version=2; PRAGMA application_id=1347572803")
			must(t, e)
			legacy := &Store{db: db, now: time.Now}
			user := NewID()
			must(t, legacy.Update(ctx, NewID(), func(tx *Tx) error { return tx.AddUser(User{user, "Existing owner", true}) }))
			if reject {
				_, e = db.Exec("CREATE TRIGGER reject_admin_migration BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END")
				must(t, e)
			}
			must(t, legacy.Close())
			s, e := Open(ctx, dir)
			if !reject {
				must(t, e)
				defer func() { _ = s.Close() }()
				var count int
				must(t, s.db.QueryRow("SELECT count(*) FROM users WHERE id=?", user).Scan(&count))
				if count != 1 {
					t.Fatal("migration lost owner")
				}
				must(t, verifyAudit(ctx, s.db))
				return
			}
			if e == nil {
				_ = s.Close()
				t.Fatal("migration ignored audit failure")
			}
			db, e = sql.Open("sqlite", databaseURI(filepath.Join(dir, "controller.sqlite")))
			must(t, e)
			defer func() { _ = db.Close() }()
			var version, tables int
			var digest string
			must(t, db.QueryRow("PRAGMA user_version").Scan(&version))
			must(t, db.QueryRow("SELECT schema_digest FROM meta").Scan(&digest))
			must(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='admin_devices'").Scan(&tables))
			if version != 2 || digest != old || tables != 0 {
				t.Fatal("partial administrator migration committed")
			}
			must(t, verifyAudit(ctx, db))
		})
	}
}
