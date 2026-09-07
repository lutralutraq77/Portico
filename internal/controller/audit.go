package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
)

type Checkpoint struct {
	Sequence int64
	Hash     string
}
type Event struct {
	Sequence                                 int64
	ID                                       string
	OccurredAt                               int64
	ActorID, CorrelationID, Action, TargetID string
	Generation                               int64
	PreviousHash, Hash                       string
}

func eventHash(e Event) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// VerifyBatch validates continuity against a checkpoint held independently.
// A hash chain does not stop root from rewriting history and its local head.
func VerifyBatch(start Checkpoint, events []Event) (Checkpoint, error) {
	if start.Sequence < 0 || (start.Sequence == 0 && start.Hash != "") || (start.Sequence > 0 && !digest(start.Hash)) {
		return start, ErrIntegrity
	}
	for _, e := range events {
		if e.Sequence != start.Sequence+1 || e.PreviousHash != start.Hash || e.Hash != eventHash(e) {
			return start, ErrIntegrity
		}
		start = Checkpoint{e.Sequence, e.Hash}
	}
	return start, nil
}
func (t *Tx) event(action, target string) error {
	if e := t.guard(validID(target)); e != nil {
		return e
	}
	if e := t.exec("UPDATE meta SET generation=generation+1 WHERE singleton=1"); e != nil {
		return e
	}
	var seq, gen, previousTime int64
	var prev string
	if e := t.tx.QueryRowContext(t.ctx, "SELECT audit_sequence,audit_hash,generation FROM meta WHERE singleton=1").Scan(&seq, &prev, &gen); e != nil {
		return t.fail(ErrStorage)
	}
	if seq > 0 {
		if e := t.tx.QueryRowContext(t.ctx, "SELECT occurred_at FROM audit_events WHERE sequence=?", seq).Scan(&previousTime); e != nil {
			return t.fail(ErrIntegrity)
		}
		if t.now.UnixNano() < previousTime {
			return t.fail(ErrDenied)
		}
	}
	ev := Event{Sequence: seq + 1, ID: NewID(), OccurredAt: t.now.UnixNano(), ActorID: t.actor, CorrelationID: t.correlation, Action: action, TargetID: target, Generation: gen, PreviousHash: prev}
	ev.Hash = eventHash(ev)
	if e := t.exec("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?,?,?)", ev.Sequence, ev.ID, ev.OccurredAt, ev.ActorID, ev.CorrelationID, ev.Action, ev.TargetID, ev.Generation, ev.PreviousHash, ev.Hash); e != nil {
		return e
	}
	if e := t.exec("UPDATE meta SET audit_sequence=?,audit_hash=? WHERE singleton=1", ev.Sequence, ev.Hash); e != nil {
		return e
	}
	t.audited = true
	return nil
}

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func eventsAfter(ctx context.Context, q querier, after int64, limit int) ([]Event, error) {
	rows, e := q.QueryContext(ctx, "SELECT sequence,event_id,occurred_at,actor_id,correlation_id,action,target_id,generation,previous_hash,hash FROM audit_events WHERE sequence>? ORDER BY sequence LIMIT ?", after, limit)
	if e != nil {
		return nil, ErrStorage
	}
	defer func() { _ = rows.Close() }()
	events := []Event{}
	for rows.Next() {
		var v Event
		if e = rows.Scan(&v.Sequence, &v.ID, &v.OccurredAt, &v.ActorID, &v.CorrelationID, &v.Action, &v.TargetID, &v.Generation, &v.PreviousHash, &v.Hash); e != nil {
			return nil, ErrIntegrity
		}
		events = append(events, v)
	}
	if rows.Err() != nil {
		return nil, ErrStorage
	}
	return events, nil
}
func verifyAudit(ctx context.Context, q querier) error {
	var head Checkpoint
	if e := q.QueryRowContext(ctx, "SELECT audit_sequence,audit_hash FROM meta WHERE singleton=1").Scan(&head.Sequence, &head.Hash); e != nil {
		return ErrIntegrity
	}
	cursor := Checkpoint{}
	for cursor.Sequence < head.Sequence {
		events, e := eventsAfter(ctx, q, cursor.Sequence, 256)
		if e != nil {
			return e
		}
		if len(events) == 0 {
			return ErrIntegrity
		}
		cursor, e = VerifyBatch(cursor, events)
		if e != nil {
			return e
		}
	}
	if cursor != head {
		return ErrIntegrity
	}
	var count int64
	if e := q.QueryRowContext(ctx, "SELECT count(*) FROM audit_events").Scan(&count); e != nil || count != head.Sequence {
		return ErrIntegrity
	}
	return nil
}

// AuditBatch reads immutable outbox records; callers retain their checkpoint
// independently and acknowledge only after successful durable export.
func (s *Store) AuditBatch(ctx context.Context, start Checkpoint, limit int) ([]Event, error) {
	if limit < 1 || limit > 256 {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	if e = verifyAudit(ctx, tx); e != nil {
		return nil, e
	}
	events, e := eventsAfter(ctx, tx, start.Sequence, limit)
	if e != nil {
		return nil, e
	}
	if start.Sequence > 0 {
		var got string
		if e = tx.QueryRowContext(ctx, "SELECT hash FROM audit_events WHERE sequence=?", start.Sequence).Scan(&got); e != nil || got != start.Hash {
			return nil, ErrIntegrity
		}
	}
	if _, e = VerifyBatch(start, events); e != nil {
		return nil, e
	}
	return events, classify(tx.Commit())
}
func (s *Store) Acknowledge(ctx context.Context, previous, next Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }()
	var current Checkpoint
	if e = tx.QueryRowContext(ctx, "SELECT export_sequence,export_hash FROM meta WHERE singleton=1").Scan(&current.Sequence, &current.Hash); e != nil {
		return ErrStorage
	}
	if current != previous || next.Sequence <= previous.Sequence || next.Sequence-previous.Sequence > 256 {
		return ErrConflict
	}
	events, e := eventsAfter(ctx, tx, previous.Sequence, int(next.Sequence-previous.Sequence))
	if e != nil {
		return e
	}
	end, e := VerifyBatch(previous, events)
	if e != nil || end != next {
		return ErrIntegrity
	}
	if _, e = tx.ExecContext(ctx, "UPDATE meta SET export_sequence=?,export_hash=? WHERE singleton=1", next.Sequence, next.Hash); e != nil {
		return ErrStorage
	}
	return classify(tx.Commit())
}
