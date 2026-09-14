package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

//go:embed enrollment.sql
var enrollmentSchema string

//go:embed admin.sql
var adminSchema string

//go:embed policy.sql
var policySchema string

//go:embed closure.sql
var closureSchema string

const applicationID = 0x50525443
const schemaVersion = 5

func currentSchemaDigest() string {
	h := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema + policySchema + closureSchema))
	return hex.EncodeToString(h[:])
}

type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	emergency atomic.Bool
	now       func() time.Time
	signalMu  sync.Mutex
	changed   chan struct{}
}

// Open opens one controller's local directory, never a URI or network database.
// The caller must enforce directory ownership/ACLs and single-process ownership.
func Open(ctx context.Context, directory string) (*Store, error) {
	if !filepath.IsAbs(directory) || strings.HasPrefix(directory, "\\\\") {
		return nil, ErrInvalid
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, ErrStorage
	}
	path := filepath.Join(directory, "controller.sqlite")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, ErrStorage
	}
	if e = f.Close(); e != nil {
		return nil, ErrStorage
	}
	db, e := sql.Open("sqlite", databaseURI(path))
	if e != nil {
		return nil, ErrStorage
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, now: time.Now}
	if e = s.initialize(ctx); e != nil {
		_ = db.Close()
		return nil, e
	}
	return s, nil
}
func classify(e error) error {
	if e == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(e, &se) && se.Code()&255 == 19 {
		return ErrConflict
	}
	return ErrStorage
}
func (s *Store) initialize(ctx context.Context) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	var version, app int
	if e = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return ErrStorage
	}
	if e = tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); e != nil {
		return ErrStorage
	}
	want := currentSchemaDigest()
	if version == 0 && app == 0 {
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&n); e != nil || n != 0 {
			return ErrIntegrity
		}
		if _, e = tx.ExecContext(ctx, schema+enrollmentSchema+adminSchema+policySchema+closureSchema); e != nil {
			return classify(e)
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO meta(singleton,schema_digest) VALUES(1,?)", want); e != nil {
			return ErrStorage
		}
		if _, e = tx.ExecContext(ctx, "PRAGMA user_version=5; PRAGMA application_id=1347572803"); e != nil {
			return ErrStorage
		}
	} else if (version < 1 || version > schemaVersion) || app != applicationID {
		return ErrIntegrity
	}
	var got string
	var quarantined int
	if e = tx.QueryRowContext(ctx, "SELECT schema_digest,quarantined FROM meta WHERE singleton=1").Scan(&got, &quarantined); e != nil {
		return ErrIntegrity
	}
	old := sha256.Sum256([]byte(schema))
	if version == 1 {
		if got != hex.EncodeToString(old[:]) {
			return ErrIntegrity
		}
	} else if version == 2 {
		previous := sha256.Sum256([]byte(schema + enrollmentSchema))
		if got != hex.EncodeToString(previous[:]) {
			return ErrIntegrity
		}
	} else if version == 3 {
		previous := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema))
		if got != hex.EncodeToString(previous[:]) {
			return ErrIntegrity
		}
	} else if version == 4 {
		previous := sha256.Sum256([]byte(schema + enrollmentSchema + adminSchema + policySchema))
		if got != hex.EncodeToString(previous[:]) {
			return ErrIntegrity
		}
	} else if got != want {
		return ErrIntegrity
	}
	if quarantined != 0 {
		return ErrQuarantine
	}
	var check string
	if e = tx.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); e != nil || check != "ok" {
		return ErrIntegrity
	}
	rows, e := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return ErrIntegrity
	}
	bad := rows.Next()
	rowerr := rows.Err()
	_ = rows.Close()
	if bad || rowerr != nil {
		return ErrIntegrity
	}
	if e = verifyAudit(ctx, tx); e != nil {
		return e
	}
	if version >= 1 && version < schemaVersion {
		migration := closureSchema
		if version <= 3 {
			migration = policySchema + migration
		}
		if version <= 2 {
			migration = adminSchema + migration
		}
		if version == 1 {
			migration = enrollmentSchema + migration
		}
		if _, e = tx.ExecContext(ctx, migration); e != nil {
			return ErrStorage
		}
		// Pending approvals must be recreated against the upgraded security
		// boundary. Earlier versions also used a different binding revision.
		if _, e = tx.ExecContext(ctx, "DELETE FROM admin_ceremonies"); e != nil {
			return ErrStorage
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM policy_previews"); e != nil {
			return ErrStorage
		}
		if _, e = tx.ExecContext(ctx, "UPDATE meta SET schema_digest=? WHERE singleton=1", want); e != nil {
			return ErrStorage
		}
		if _, e = tx.ExecContext(ctx, "PRAGMA user_version=5"); e != nil {
			return ErrStorage
		}
		t := &Tx{tx: tx, ctx: ctx, now: s.now().UTC(), actor: NewID(), correlation: NewID()}
		if e = t.event("schema.security", t.actor); e != nil {
			return e
		}
	}
	// Leases never survive process restart. Phase 2 records have no forwarding authority.
	var live int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE state='requested'").Scan(&live); e != nil {
		return ErrStorage
	}
	if live > 0 {
		t := &Tx{tx: tx, ctx: ctx, now: s.now().UTC(), actor: NewID(), correlation: NewID()}
		if e = t.exec("UPDATE sessions SET state='closed' WHERE state='requested'"); e != nil {
			return e
		}
		if e = t.event("restart.close", t.actor); e != nil {
			return e
		}
	}
	return classify(tx.Commit())
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := classify(s.db.Close())
	s.signalChange()
	return e
}

// The notification lock is independent of the database lock: emergency deny
// must wake long polls even while a storage operation is stalled. The durable
// cancellation table remains the source of truth; this is only a wakeup hint.
func (s *Store) changes() <-chan struct{} {
	s.signalMu.Lock()
	defer s.signalMu.Unlock()
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	return s.changed
}
func (s *Store) signalChange() {
	s.signalMu.Lock()
	defer s.signalMu.Unlock()
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

// EmergencyDeny latches an immediate, process-local stop, including when storage
// fails. It cannot claim durable revocation or remote socket closure.
func (s *Store) EmergencyDeny() { s.emergency.Store(true); s.signalChange() }
func (s *Store) Stopped() bool  { return s.emergency.Load() }

// Update is a trusted local transaction boundary, not an admin/API endpoint.
// Every mutation appends its allowlisted audit intent in the same transaction.
// Authenticated entry points verify their transport and hardware proofs before
// invoking mutations. This low-level API is restricted to trusted local code.
func (s *Store) Update(ctx context.Context, actor string, change func(*Tx) error) error {
	if !validID(actor) || change == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.emergency.Load() {
		return ErrDenied
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	t := &Tx{tx: tx, ctx: ctx, now: s.now().UTC(), actor: actor, correlation: NewID()}
	defer func() { t.closed = true }()
	// Read-only identity checks also fail closed if wall time precedes durable
	// security history. Full clock-health qualification remains a deployment gate.
	var previousTime int64
	e = tx.QueryRowContext(ctx, "SELECT occurred_at FROM audit_events ORDER BY sequence DESC LIMIT 1").Scan(&previousTime)
	if e != nil && e != sql.ErrNoRows {
		return ErrStorage
	}
	if e == nil && t.now.UnixNano() < previousTime {
		return ErrDenied
	}
	if e = change(t); e != nil {
		return e
	}
	if t.err != nil {
		return t.err
	}
	if s.emergency.Load() {
		return ErrDenied
	}
	e = classify(tx.Commit())
	if e == nil && t.audited {
		s.signalChange()
	}
	return e
}

type Tx struct {
	tx                 *sql.Tx
	ctx                context.Context
	now                time.Time
	actor, correlation string
	err                error
	closed             bool
	audited            bool
}

func (t *Tx) fail(e error) error {
	if t.err == nil {
		t.err = e
	}
	return e
}
func (t *Tx) exec(query string, args ...any) error {
	if t.closed {
		return t.fail(ErrDenied)
	}
	if t.err != nil {
		return t.err
	}
	_, e := t.tx.ExecContext(t.ctx, query, args...)
	if e != nil {
		return t.fail(classify(e))
	}
	return nil
}
func (t *Tx) guard(ok bool) error {
	if t.closed {
		return t.fail(ErrDenied)
	}
	if t.err != nil {
		return t.err
	}
	if !ok {
		return t.fail(ErrInvalid)
	}
	return nil
}
func (t *Tx) current(id string, revision int64) error {
	var got int64
	if e := t.tx.QueryRowContext(t.ctx, "SELECT revision FROM resource_heads WHERE id=?", id).Scan(&got); e != nil || got != revision {
		return t.fail(ErrConflict)
	}
	return nil
}
func (s *Store) Summary(ctx context.Context) (Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v Summary
	var q int
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return v, ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	for i, table := range []string{"users", "devices", "connectors", "resource_heads", "grants", "certificates", "sessions"} {
		ptr := []*int{&v.Users, &v.Devices, &v.Connectors, &v.Resources, &v.Grants, &v.Certificates, &v.Sessions}[i]
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(ptr); e != nil {
			return Summary{}, ErrStorage
		}
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE state='requested'").Scan(&v.OpenSessions); e != nil {
		return Summary{}, ErrStorage
	}
	if e = tx.QueryRowContext(ctx, "SELECT generation,audit_sequence,quarantined FROM meta WHERE singleton=1").Scan(&v.Generation, &v.AuditSequence, &q); e != nil {
		return Summary{}, ErrStorage
	}
	v.Quarantined = q != 0
	return v, classify(tx.Commit())
}
