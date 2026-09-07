CREATE TABLE pki_bindings (
 issuer_id TEXT PRIMARY KEY REFERENCES issuers(id), deployment_id TEXT NOT NULL,
 profile TEXT NOT NULL CHECK(profile IN ('device','connector')),
 root_sha256 TEXT NOT NULL CHECK(length(root_sha256)=64),
 issuer_sha256 TEXT NOT NULL UNIQUE CHECK(length(issuer_sha256)=64)
) STRICT;
CREATE TABLE enrollments (
 id TEXT PRIMARY KEY, issuer_id TEXT NOT NULL REFERENCES pki_bindings(issuer_id),
 device_id TEXT REFERENCES devices(id), connector_id TEXT REFERENCES connectors(id),
 token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, not_after INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('invited','reserved','issuing','issued','active','failed','revoked')),
 attempt_id TEXT UNIQUE, spki_sha256 TEXT, csr_der BLOB,
 certificate_id TEXT UNIQUE REFERENCES certificates(id), certificate_der BLOB,
 replaces_certificate_id TEXT REFERENCES certificates(id),
 CHECK((device_id IS NOT NULL AND connector_id IS NULL) OR (device_id IS NULL AND connector_id IS NOT NULL)),
 CHECK(expires_at>created_at AND not_after>created_at),
 CHECK((attempt_id IS NULL AND spki_sha256 IS NULL AND csr_der IS NULL) OR (attempt_id IS NOT NULL AND length(spki_sha256)=64 AND length(csr_der)>0 AND length(csr_der)<=4096)),
 CHECK((certificate_id IS NULL AND certificate_der IS NULL) OR (certificate_id IS NOT NULL AND length(certificate_der)>0 AND length(certificate_der)<=16384)),
 CHECK(state NOT IN ('reserved','issuing','issued','active') OR attempt_id IS NOT NULL),
 CHECK(state NOT IN ('issued','active') OR certificate_id IS NOT NULL)
) STRICT;
