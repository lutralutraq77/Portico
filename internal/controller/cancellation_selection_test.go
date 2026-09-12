package controller

import (
	"testing"
	"time"

	"portico.local/portico/internal/pki"
)

func TestCancellationSelectionCannotBeStarvedByUnknownReceipts(t *testing.T) {
	v := newPolicyFixture(t)
	v.engine.config.LeaseLifetime = 15 * time.Second
	// Earlier processes may have closed sessions without delivering receipts.
	// Retain more of those tombstones than fit in one ordinary batch.
	for i := 0; i <= MaxCancellationBatch; i++ {
		a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
		must(t, e)
		must(t, v.engine.CloseSession(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: a.Sequence}))
	}
	a, e := v.engine.Authorize(ctx, v.connectorConn, v.request())
	must(t, e)
	client, _ := serveControlClient(t, v, pki.Connector)
	r := CancellationRequest{Version: 1, Limit: 1, WaitMillis: 1000, SessionIDs: []string{a.SessionID}}
	read := observePolicyRead(v.device.f.s)
	type response struct {
		batch CancellationBatch
		err   error
	}
	done := make(chan response, 1)
	go func() {
		batch, err := client.Cancellations(ctx, r)
		done <- response{batch, err}
	}()
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("selected poll did not reach controller")
	}
	select {
	case <-done:
		t.Fatal("old unknown sessions interrupted the selected long poll")
	case <-time.After(30 * time.Millisecond):
	}
	must(t, v.engine.CloseSession(ctx, v.connectorConn, SessionRequest{Version: 1, SessionID: a.SessionID, Sequence: a.Sequence}))
	select {
	case got := <-done:
		must(t, got.err)
		if len(got.batch.Items) != 1 || got.batch.Items[0].SessionID != a.SessionID {
			t.Fatal("older unknown receipts starved the tracked session")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("selected cancellation was not delivered")
	}
	// The owner retries after a lost response. Selection changes neither
	// ownership nor the repeat-until-acknowledged rule.
	r.WaitMillis = 0
	batch, e := client.Cancellations(ctx, r)
	must(t, e)
	if len(batch.Items) != 1 || batch.Items[0].SessionID != a.SessionID {
		t.Fatal("selection skipped a retried response")
	}
	other, _, _ := enrolledPolicyPeer(t, v.connector, v.device.f.connector.ID)
	batch, e = v.engine.Cancellations(ctx, other, r)
	must(t, e)
	if len(batch.Items) != 0 {
		t.Fatal("replacement certificate selected another certificate's session")
	}
	if e = v.engine.AcknowledgeCancellation(ctx, other, CancellationAck{Version: 1, SessionID: a.SessionID}); e == nil {
		t.Fatal("replacement certificate reported another certificate's closure")
	}
	must(t, client.AcknowledgeCancellation(ctx, CancellationAck{Version: 1, SessionID: a.SessionID}))
	batch, e = client.Cancellations(ctx, r)
	must(t, e)
	if len(batch.Items) != 0 {
		t.Fatal("acknowledged selection remained pending")
	}
	var pending int
	must(t, v.device.f.s.db.QueryRow(`SELECT count(*) FROM session_cancellations c LEFT JOIN session_closure_receipts r ON r.session_id=c.session_id WHERE r.session_id IS NULL`).Scan(&pending))
	if pending != MaxCancellationBatch+1 {
		t.Fatal("selection fabricated closure of unknown sessions")
	}
}

func TestCancellationSelectionBounds(t *testing.T) {
	v := newPolicyFixture(t)
	client, _ := serveControlClient(t, v, pki.Connector)
	id := NewID()
	for _, ids := range [][]string{{id, id}, {"not-an-id"}, {id, NewID(), NewID()}} {
		r := CancellationRequest{Version: 1, Limit: 2, SessionIDs: ids}
		if _, e := client.Cancellations(ctx, r); e == nil {
			t.Fatal("client accepted ambiguous, malformed or truncated selection")
		}
		if _, e := v.engine.Cancellations(ctx, v.connectorConn, r); e == nil {
			t.Fatal("controller accepted ambiguous, malformed or truncated selection")
		}
	}
	// Unknown IDs cannot disclose a foreign session or invent a tombstone.
	batch, e := client.Cancellations(ctx, CancellationRequest{Version: 1, Limit: 1, SessionIDs: []string{NewID()}})
	must(t, e)
	if len(batch.Items) != 0 {
		t.Fatal("unknown session selection returned data")
	}
}
