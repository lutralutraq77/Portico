CREATE TABLE admin_renewals (
 id TEXT PRIMARY KEY,
 device_id TEXT NOT NULL REFERENCES admin_devices(device_id),
 old_sha256 TEXT NOT NULL, old_der BLOB NOT NULL,
 csr_der BLOB NOT NULL, spki_sha256 TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 not_after INTEGER NOT NULL,
 policy_revision INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('approved','issuing','issued','active','revoked')),
 leaf_sha256 TEXT UNIQUE, certificate_der BLOB
) STRICT;
CREATE UNIQUE INDEX admin_renewal_outstanding ON admin_renewals(device_id)
 WHERE state IN ('approved','issuing','issued');
