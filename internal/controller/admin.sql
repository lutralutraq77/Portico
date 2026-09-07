CREATE TABLE admin_devices (
 device_id TEXT PRIMARY KEY REFERENCES devices(id),
 user_id TEXT NOT NULL REFERENCES users(id),
 deployment_id TEXT NOT NULL, issuer_id TEXT NOT NULL,
 root_sha256 TEXT NOT NULL, issuer_sha256 TEXT NOT NULL,
 leaf_sha256 TEXT NOT NULL UNIQUE, certificate_der BLOB NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 bootstrap_until INTEGER NOT NULL,
 FOREIGN KEY(device_id,user_id) REFERENCES devices(id,user_id)
) STRICT;
CREATE TABLE admin_factors (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 credential_id BLOB NOT NULL UNIQUE, public_key BLOB NOT NULL UNIQUE,
 credential_json BLOB NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 tested INTEGER NOT NULL CHECK(tested IN (0,1))
) STRICT;
CREATE TABLE admin_ceremonies (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES admin_devices(device_id),
 user_id TEXT NOT NULL REFERENCES users(id),
 session_json BLOB NOT NULL, operation_json BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','used')),
 expires_at INTEGER NOT NULL
) STRICT;
