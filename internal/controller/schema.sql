CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema_digest TEXT NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0,
 audit_sequence INTEGER NOT NULL DEFAULT 0,
 audit_hash TEXT NOT NULL DEFAULT '',
 export_sequence INTEGER NOT NULL DEFAULT 0,
 export_hash TEXT NOT NULL DEFAULT '',
 quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1))
) STRICT;
CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), created_at INTEGER NOT NULL) STRICT;
CREATE TABLE devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, platform TEXT NOT NULL CHECK(platform IN ('linux','windows','android')), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), not_after INTEGER NOT NULL, UNIQUE(id,user_id)) STRICT;
CREATE TABLE connectors (id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1))) STRICT;
CREATE TABLE issuers (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), not_after INTEGER NOT NULL) STRICT;
CREATE TABLE certificates (
 id TEXT PRIMARY KEY, issuer_id TEXT NOT NULL REFERENCES issuers(id), serial TEXT NOT NULL,
 device_id TEXT REFERENCES devices(id), connector_id TEXT REFERENCES connectors(id),
 profile TEXT NOT NULL CHECK(profile IN ('device','connector')),
 leaf_sha256 TEXT NOT NULL UNIQUE CHECK(length(leaf_sha256)=64),
 spki_sha256 TEXT NOT NULL CHECK(length(spki_sha256)=64),
 not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
 UNIQUE(issuer_id,serial),
 CHECK(not_after>not_before),
 CHECK((profile='device' AND device_id IS NOT NULL AND connector_id IS NULL) OR (profile='connector' AND device_id IS NULL AND connector_id IS NOT NULL))
) STRICT;
CREATE TABLE resources (
 id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), name TEXT NOT NULL,
 connector_id TEXT NOT NULL REFERENCES connectors(id), kind TEXT NOT NULL CHECK(kind IN ('application','management')),
 address TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 protocol TEXT NOT NULL CHECK(protocol='tcp'), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 PRIMARY KEY(id,revision), UNIQUE(id,revision,connector_id)
) STRICT;
CREATE TABLE resource_heads (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, FOREIGN KEY(id,revision) REFERENCES resources(id,revision)) STRICT;
CREATE TABLE grants (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL,
 resource_id TEXT NOT NULL, revision INTEGER NOT NULL, approval_id TEXT NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 CHECK(valid_until>valid_from),
 FOREIGN KEY(device_id,user_id) REFERENCES devices(id,user_id),
 FOREIGN KEY(resource_id,revision) REFERENCES resources(id,revision)
) STRICT;
CREATE TABLE host_bindings (
 id TEXT PRIMARY KEY, connector_id TEXT NOT NULL, resource_id TEXT NOT NULL, revision INTEGER NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL,
 CHECK(valid_until>valid_from),
 FOREIGN KEY(resource_id,revision,connector_id) REFERENCES resources(id,revision,connector_id)
) STRICT;
CREATE TABLE sessions (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 certificate_id TEXT NOT NULL REFERENCES certificates(id),
 connector_certificate_id TEXT NOT NULL REFERENCES certificates(id),
 resource_id TEXT NOT NULL, revision INTEGER NOT NULL,
 grant_id TEXT NOT NULL REFERENCES grants(id), host_binding_id TEXT NOT NULL REFERENCES host_bindings(id),
 state TEXT NOT NULL CHECK(state IN ('requested','denied','expired','closed')),
 created_at INTEGER NOT NULL, not_after INTEGER NOT NULL,
 FOREIGN KEY(resource_id,revision) REFERENCES resources(id,revision),
 CHECK(not_after>created_at)
) STRICT;
CREATE TABLE audit_events (
 sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, occurred_at INTEGER NOT NULL,
 actor_id TEXT NOT NULL, correlation_id TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL,
 generation INTEGER NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL
) STRICT;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
