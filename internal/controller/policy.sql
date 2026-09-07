CREATE TABLE policy_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=0)) STRICT;
INSERT INTO policy_meta VALUES(1,1);
CREATE TABLE authorized_sessions (
 id TEXT PRIMARY KEY REFERENCES sessions(id),
 connector_id TEXT NOT NULL REFERENCES connectors(id),
 address TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 protocol TEXT NOT NULL CHECK(protocol='tcp'),
 state TEXT NOT NULL CHECK(state IN ('authorized','active','closed')),
 lease_sequence INTEGER NOT NULL CHECK(lease_sequence>0),
 lease_until INTEGER NOT NULL, activate_until INTEGER NOT NULL,
 policy_revision INTEGER NOT NULL, config_sha256 TEXT NOT NULL CHECK(length(config_sha256)=64)
) STRICT;
CREATE INDEX authorized_sessions_connector ON authorized_sessions(connector_id,state,lease_until);
CREATE TABLE session_cancellations (session_id TEXT PRIMARY KEY REFERENCES authorized_sessions(id), reason TEXT NOT NULL CHECK(reason IN ('denied','expired','closed'))) STRICT;
CREATE TRIGGER session_cancel AFTER UPDATE OF state ON sessions WHEN OLD.state='requested' AND NEW.state<>'requested'
BEGIN
 INSERT OR IGNORE INTO session_cancellations SELECT id,NEW.state FROM authorized_sessions WHERE id=NEW.id;
 UPDATE authorized_sessions SET state='closed' WHERE id=NEW.id;
END;
CREATE TABLE policy_previews (
 id TEXT PRIMARY KEY,
 device_id TEXT NOT NULL REFERENCES admin_devices(device_id), user_id TEXT NOT NULL REFERENCES users(id),
 certificate_sha256 TEXT NOT NULL, policy_revision INTEGER NOT NULL, config_sha256 TEXT NOT NULL,
 operation_json BLOB NOT NULL, display_json BLOB NOT NULL,
 expires_at INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','used'))
) STRICT;
CREATE TRIGGER policy_users_insert AFTER INSERT ON users BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_users_update AFTER UPDATE ON users BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_users_delete AFTER DELETE ON users BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_devices_insert AFTER INSERT ON devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_devices_update AFTER UPDATE ON devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_devices_delete AFTER DELETE ON devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_connectors_insert AFTER INSERT ON connectors BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_connectors_update AFTER UPDATE ON connectors BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_connectors_delete AFTER DELETE ON connectors BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_issuers_insert AFTER INSERT ON issuers BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_issuers_update AFTER UPDATE ON issuers BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_issuers_delete AFTER DELETE ON issuers BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_certificates_insert AFTER INSERT ON certificates BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_certificates_update AFTER UPDATE ON certificates BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_certificates_delete AFTER DELETE ON certificates BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resources_insert AFTER INSERT ON resources BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resources_update AFTER UPDATE ON resources BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resources_delete AFTER DELETE ON resources BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resource_heads_insert AFTER INSERT ON resource_heads BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resource_heads_update AFTER UPDATE ON resource_heads BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_resource_heads_delete AFTER DELETE ON resource_heads BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_grants_insert AFTER INSERT ON grants BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_grants_update AFTER UPDATE ON grants BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_grants_delete AFTER DELETE ON grants BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_host_bindings_insert AFTER INSERT ON host_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_host_bindings_update AFTER UPDATE ON host_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_host_bindings_delete AFTER DELETE ON host_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_pki_bindings_insert AFTER INSERT ON pki_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_pki_bindings_update AFTER UPDATE ON pki_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_pki_bindings_delete AFTER DELETE ON pki_bindings BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_enrollments_insert AFTER INSERT ON enrollments BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_enrollments_update AFTER UPDATE ON enrollments BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_enrollments_delete AFTER DELETE ON enrollments BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_devices_insert AFTER INSERT ON admin_devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_devices_update AFTER UPDATE ON admin_devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_devices_delete AFTER DELETE ON admin_devices BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_factors_insert AFTER INSERT ON admin_factors BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_factors_update AFTER UPDATE ON admin_factors
WHEN OLD.enabled<>NEW.enabled OR OLD.tested<>NEW.tested OR OLD.user_id<>NEW.user_id OR OLD.credential_id<>NEW.credential_id OR OLD.public_key<>NEW.public_key
BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER policy_admin_factors_delete AFTER DELETE ON admin_factors BEGIN UPDATE policy_meta SET revision=revision+1 WHERE singleton=1; END;
