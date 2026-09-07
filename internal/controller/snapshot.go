package controller

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func databaseURI(path string) string {
	slash := filepath.ToSlash(path)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	q := u.Query()
	q.Set("_txlock", "immediate")
	for _, p := range []string{"foreign_keys(1)", "journal_mode(DELETE)", "synchronous(EXTRA)", "busy_timeout(5000)", "trusted_schema(0)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Snapshot writes an exclusively created, quarantined database copy. It is
// unencrypted domain data, not the Phase 3 encrypted recovery/restore protocol.
// Open deliberately refuses this copy; no unquarantine API exists in Phase 2.
func (s *Store) Snapshot(ctx context.Context, destination string) error {
	if !filepath.IsAbs(destination) || strings.HasPrefix(destination, "\\\\") {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := verifyAudit(ctx, s.db); e != nil {
		return e
	}
	staging := filepath.Join(filepath.Dir(destination), ".portico-snapshot-"+NewID()+".sqlite")
	defer func() { _ = os.Remove(staging) }()
	if _, e := s.db.ExecContext(ctx, "VACUUM main INTO ?", staging); e != nil {
		return ErrStorage
	}
	if e := os.Chmod(staging, 0600); e != nil {
		return ErrStorage
	}
	backup, e := sql.Open("sqlite", databaseURI(staging))
	if e != nil {
		return ErrStorage
	}
	backup.SetMaxOpenConns(1)
	defer func() { _ = backup.Close() }()
	tx, e := backup.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	t := &Tx{tx: tx, ctx: ctx, now: s.now().UTC(), actor: NewID(), correlation: NewID()}
	if e = t.exec("UPDATE meta SET quarantined=1 WHERE singleton=1"); e != nil {
		return e
	}
	if e = t.exec("UPDATE sessions SET state='closed' WHERE state='requested'"); e != nil {
		return e
	}
	if e = t.event("snapshot.quarantine", t.actor); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrStorage
	}
	if e = backup.Close(); e != nil {
		return ErrStorage
	}
	// A hard link publishes without overwriting an existing destination.
	if e = os.Link(staging, destination); e != nil {
		return ErrStorage
	}
	return nil
}
