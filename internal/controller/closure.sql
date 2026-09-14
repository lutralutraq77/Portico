-- Receipts are authenticated connector reports, distinct from controller denial.
-- A report never grants authority, changes a tombstone, or reopens a session.
CREATE TABLE session_closure_receipts (
 session_id TEXT PRIMARY KEY REFERENCES session_cancellations(session_id),
 connector_certificate_id TEXT NOT NULL REFERENCES certificates(id),
 reported_at INTEGER NOT NULL CHECK(reported_at>0)
) STRICT;
CREATE TRIGGER closure_receipt_no_update BEFORE UPDATE ON session_closure_receipts BEGIN SELECT RAISE(ABORT,'immutable closure receipt'); END;
CREATE TRIGGER closure_receipt_no_delete BEFORE DELETE ON session_closure_receipts BEGIN SELECT RAISE(ABORT,'immutable closure receipt'); END;
