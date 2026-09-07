package controller

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionThreeMigrationPreservesFactorsAndInvalidatesChallenges(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "migrate", true: "rollback"}[reject], func(t *testing.T) {
			a := adminSeed(t)
			a.setupFactors(t)
			c := a.begin(t, a.invitation())
			response := a.assertion(t, a.keys[0], c)
			s := a.f.f.s
			before := summary(t, s)
			// Remove precisely the newly introduced objects to reconstruct the
			// v3 schema while retaining real enrolled administrator/key records.
			rows, e := s.db.Query("SELECT name FROM sqlite_master WHERE type='trigger' AND (name LIKE 'policy_%' OR name='session_cancel')")
			must(t, e)
			var names []string
			for rows.Next() {
				var name string
				must(t, rows.Scan(&name))
				names = append(names, name)
			}
			must(t, rows.Err())
			must(t, rows.Close())
			for _, name := range names {
				if !strings.HasPrefix(name, "policy_") && name != "session_cancel" {
					t.Fatal("unexpected fixture trigger")
				}
				_, e = s.db.Exec(`DROP TRIGGER "` + strings.ReplaceAll(name, `"`, `""`) + `"`)
				must(t, e)
			}
			_, e = s.db.Exec("DROP TABLE session_cancellations; DROP TABLE authorized_sessions; DROP TABLE policy_previews; DROP TABLE policy_meta; PRAGMA user_version=3")
			must(t, e)
			hash := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema))
			old := hex.EncodeToString(hash[:])
			_, e = s.db.Exec("UPDATE meta SET schema_digest=?", old)
			must(t, e)
			if reject {
				_, e = s.db.Exec("CREATE TRIGGER reject_policy_migration BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'synthetic migration failure'); END")
				must(t, e)
			}
			must(t, s.Close())
			reopened, e := Open(ctx, a.f.f.dir)
			if reject {
				if e == nil {
					_ = reopened.Close()
					t.Fatal("migration ignored audit failure")
				}
				db, e := sql.Open("sqlite", databaseURI(filepath.Join(a.f.f.dir, "controller.sqlite")))
				must(t, e)
				defer func() { _ = db.Close() }()
				var version, tables, challenges int
				var got string
				must(t, db.QueryRow("PRAGMA user_version").Scan(&version))
				must(t, db.QueryRow("SELECT schema_digest FROM meta").Scan(&got))
				must(t, db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('policy_meta','authorized_sessions','session_cancellations','policy_previews')").Scan(&tables))
				must(t, db.QueryRow("SELECT count(*) FROM admin_ceremonies WHERE id=? AND state='pending'", c.ID).Scan(&challenges))
				if version != 3 || tables != 0 || got != old || challenges != 1 {
					t.Fatal("partial migration escaped rollback")
				}
				must(t, verifyAudit(ctx, db))
				return
			}
			must(t, e)
			defer func() { _ = reopened.Close() }()
			var factors, ceremonies, revision int
			must(t, reopened.db.QueryRow("SELECT count(*) FROM admin_factors WHERE enabled=1 AND tested=1").Scan(&factors))
			must(t, reopened.db.QueryRow("SELECT count(*) FROM admin_ceremonies").Scan(&ceremonies))
			must(t, reopened.db.QueryRow("SELECT revision FROM policy_meta").Scan(&revision))
			after := summary(t, reopened)
			if factors != 2 || ceremonies != 0 || revision != 1 || after.AuditSequence != before.AuditSequence+1 {
				t.Fatal("migration lost factors or retained old approvals")
			}
			if _, e = reopened.FinishAdminOperation(ctx, a.conn, a.trust, a.verifier, c.ID, response); e == nil {
				t.Fatal("pre-upgrade approval survived")
			}
			a.f.f.s = reopened
			// An existing administrator can immediately create a fresh approval;
			// no unrelated authority mutation is needed to initialize its revision.
			a.verifyKey(t, a.keys[1], a.factors[1])
			must(t, verifyAudit(ctx, reopened.db))
		})
	}
}

func TestPolicySnapshotQuarantinesSessionsAndPreviews(t *testing.T) {
	a := adminSeed(t)
	v := policyFixtureFor(t, a.f)
	a.setupFactors(t)
	previewPolicy(t, a, v.engine, resourceDraft(a.f.f))
	permit, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	_, e = v.engine.Activate(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: 1})
	must(t, e)
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.sqlite")
	must(t, a.f.f.s.Snapshot(ctx, path))
	db, e := sql.Open("sqlite", databaseURI(path))
	must(t, e)
	defer func() { _ = db.Close() }()
	var live, previews, cancellations int
	must(t, db.QueryRow("SELECT count(*) FROM authorized_sessions WHERE state<>'closed'").Scan(&live))
	must(t, db.QueryRow("SELECT count(*) FROM policy_previews").Scan(&previews))
	must(t, db.QueryRow("SELECT count(*) FROM session_cancellations WHERE session_id=?", permit.SessionID).Scan(&cancellations))
	if live != 0 || previews != 0 || cancellations != 1 {
		t.Fatal("snapshot retained forwarding or approval authority")
	}
	must(t, verifyAudit(ctx, db))
	if s, e := Open(ctx, dir); e != ErrQuarantine {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("snapshot escaped quarantine")
	}
	// Export must not revoke the live controller's authority.
	_, e = v.engine.Renew(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: permit.SessionID, Sequence: 2})
	must(t, e)
}
