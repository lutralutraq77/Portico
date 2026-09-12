package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func changedNow(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestCancellationNotificationFollowsCommit(t *testing.T) {
	f := seed(t)
	s := f.s
	changed := s.changes()
	must(t, s.Update(ctx, f.actor, func(tx *Tx) error { return nil }))
	if changedNow(changed) {
		t.Fatal("read-only transaction woke waiters")
	}
	if e := s.Update(ctx, f.actor, func(tx *Tx) error {
		if e := tx.Disable("grant", f.grant.ID); e != nil {
			return e
		}
		if changedNow(changed) {
			t.Fatal("notification preceded commit")
		}
		return ErrInvalid
	}); e != ErrInvalid {
		t.Fatal("expected transaction rollback")
	}
	if changedNow(changed) {
		t.Fatal("rolled-back mutation woke waiters")
	}
	var enabled int
	must(t, s.db.QueryRow("SELECT enabled FROM grants WHERE id=?", f.grant.ID).Scan(&enabled))
	if enabled != 1 {
		t.Fatal("rollback lost authority state")
	}
	must(t, s.Update(ctx, f.actor, func(tx *Tx) error { return tx.Disable("grant", f.grant.ID) }))
	if !changedNow(changed) || changedNow(s.changes()) {
		t.Fatal("committed change did not rotate notification generation")
	}
	// A stop must notify even when an unrelated storage operation holds mu.
	changed = s.changes()
	s.mu.Lock()
	s.EmergencyDeny()
	woke := changedNow(changed)
	s.mu.Unlock()
	if !woke || !s.Stopped() {
		t.Fatal("emergency stop depended on database lock")
	}
	changed = s.changes()
	must(t, s.Close())
	if !changedNow(changed) {
		t.Fatal("database close left waiters asleep")
	}
}

// Observe the authoritative read under the existing store lock. This avoids
// guessing when the HTTP handshake or initial transaction has completed.
func observePolicyRead(s *Store) <-chan struct{} {
	read := make(chan struct{}, 1)
	s.mu.Lock()
	previous := s.now
	s.now = func() time.Time {
		select {
		case read <- struct{}{}:
		default:
		}
		return previous()
	}
	s.mu.Unlock()
	return read
}

func TestCancellationLongPollRechecksLiveState(t *testing.T) {
	for _, action := range []string{"grant", "connector", "emergency", "cancel", "timeout"} {
		t.Run(action, func(t *testing.T) {
			v := newPolicyFixture(t)
			// Keep the session alive for the deliberately delayed poll. This is
			// a control-delivery test, not the full forwarding termination SLA.
			v.engine.config.LeaseLifetime = 15 * time.Second
			client, _ := serveControlClient(t, v, pki.Connector)
			a, e := client.Authorize(ctx, v.request())
			must(t, e)
			s := v.device.f.s
			read := observePolicyRead(s)
			pollCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			type result struct {
				batch CancellationBatch
				err   error
			}
			finished := make(chan result, 1)
			go func() {
				batch, err := client.Cancellations(pollCtx, CancellationRequest{Version: 1, Limit: 64, WaitMillis: 1000})
				finished <- result{batch, err}
			}()
			select {
			case <-read:
			case <-time.After(5 * time.Second):
				t.Fatal("poll did not reach live database check")
			}
			select {
			case <-finished:
				t.Fatal("empty poll returned before waiting")
			case <-time.After(30 * time.Millisecond):
			}
			switch action {
			case "grant":
				must(t, s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.Disable("grant", v.device.f.grant.ID) }))
			case "connector":
				must(t, s.Update(ctx, v.device.f.actor, func(tx *Tx) error { return tx.Disable("connector", v.device.f.connector.ID) }))
			case "emergency":
				s.EmergencyDeny()
			case "cancel":
				cancel()
			}
			select {
			case got := <-finished:
				switch action {
				case "grant":
					must(t, got.err)
					if len(got.batch.Items) != 1 || got.batch.Items[0].SessionID != a.SessionID {
						t.Fatal("committed cancellation was not delivered")
					}
					// Simulate losing the previous response: polling again must
					// return the same unacknowledged target without a cursor.
					retry, e := client.Cancellations(ctx, CancellationRequest{Version: 1, Limit: 64, WaitMillis: 1000})
					must(t, e)
					if len(retry.Items) != 1 || retry.Items[0] != got.batch.Items[0] {
						t.Fatal("lost response skipped cancellation")
					}
				case "timeout":
					must(t, got.err)
					if len(got.batch.Items) != 0 {
						t.Fatal("timeout invented a cancellation")
					}
				default:
					if got.err == nil || got.batch.ConnectorCertificateID != "" {
						t.Fatal("cancelled or revoked poll returned authority")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("bounded poll did not finish")
			}
		})
	}
}

func TestCancellationLongPollBounds(t *testing.T) {
	v := newPolicyFixture(t)
	client, _ := serveControlClient(t, v, pki.Connector)
	for _, r := range []CancellationRequest{
		{Version: 2, Limit: 1}, {Version: 1, Limit: 0}, {Version: 1, Limit: 65},
		{Version: 1, Limit: 1, WaitMillis: -1}, {Version: 1, Limit: 1, WaitMillis: 1001},
	} {
		if _, e := v.engine.Cancellations(ctx, v.connectorConn, r); e == nil {
			t.Fatal("server accepted invalid long poll")
		}
		if _, e := client.Cancellations(ctx, r); e == nil {
			t.Fatal("client accepted invalid long poll")
		}
	}
	batch, e := v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 1})
	must(t, e)
	// Occupied slots are tied to the authenticated certificate, not the
	// transport connection. An exhausted peer must still be able to poll
	// immediately, and release must leave no per-certificate map entries.
	for i := 0; i < maxCertificateWaits; i++ {
		if !v.engine.acquireWait(batch.ConnectorCertificateID) {
			t.Fatal("cannot occupy wait slot")
		}
	}
	if _, e = v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 1, WaitMillis: 1}); e == nil {
		t.Fatal("per-certificate wait limit bypassed")
	}
	if _, e = v.engine.Cancellations(ctx, v.connectorConn, CancellationRequest{Version: 1, Limit: 1}); e != nil {
		t.Fatal("wait saturation blocked immediate polling")
	}
	for i := 0; i < maxCertificateWaits; i++ {
		v.engine.releaseWait(batch.ConnectorCertificateID)
	}
	for i := 0; i < maxCancellationWaits; i++ {
		if !v.engine.acquireWait(fmt.Sprint(i)) {
			t.Fatal("global wait bound incorrect")
		}
	}
	if v.engine.acquireWait(batch.ConnectorCertificateID) {
		t.Fatal("global wait bound bypassed")
	}
	for i := 0; i < maxCancellationWaits; i++ {
		v.engine.releaseWait(fmt.Sprint(i))
	}
	if v.engine.waitCount != 0 || len(v.engine.waits) != 0 {
		t.Fatal("released waiters leaked capacity")
	}
}
