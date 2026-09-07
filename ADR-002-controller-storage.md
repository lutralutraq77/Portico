# ADR-002: controller domain storage

Status: accepted for Phase 2 local development on 2026-09-07. Resolves Q09 for the initial controller; supported deployment and encrypted recovery qualification remain later gates.

## Decision

Use database/sql with modernc.org/sqlite v1.58.0, its exact modernc.org/libc v1.75.6 requirement, and github.com/google/uuid v1.6.0 for random IDs. Pin the complete graph in go.mod/go.sum. The controller package owns SQL and exposes trusted typed transaction operations.

Choose SQLite on a local filesystem, one controller process and one database connection. Set foreign_keys=ON, journal_mode=DELETE, synchronous=EXTRA, a bounded busy timeout and immediate write transactions on each connection. SQL values are parameters; table names come only from fixed internal allowlists. Resource endpoint revisions are retained, grants and HostBindings reference exact revisions, and there is no delete/reuse API.

The initial migration runs transactionally and stamps an application ID, schema version and migration digest. Unknown versions, wrong application identity, inconsistent audit history and failed integrity checks reject opening. No automatic downgrade or destructive repair exists.

Every successful domain mutation writes an allowlisted audit event and advances generation in the same transaction. Ignored method errors poison the entire transaction. Events form a SHA-256 integrity chain with sequential export checkpoints; this is not an authenticated log and cannot defeat root rewriting both history and its local head.

## Alternatives and cost

mattn/go-sqlite3 would introduce a C toolchain dependency into controller builds and cross-compilation. modernc removes that build requirement while retaining SQLite transaction semantics. Its generated code and transitive dependencies are substantial and require ongoing vulnerability, license and upgrade review. Separate the scanner module from runtime dependencies.

The selected upstream release documents Windows/Linux support and SQLite 3.53.4. Review relied on upstream documentation, checksum-verified module downloads and our actual Windows/Linux tests, not a claim of an independent driver audit.

## Data and recovery boundaries

The database holds controller metadata, not private device keys or invitation secrets. It is currently plaintext: directory ACLs/ownership, disk encryption and backup custody are deployment requirements. The development directory is not a qualified shared-user controller deployment.

Snapshot uses SQLite VACUUM INTO under the store lock, then marks the copy quarantined and closes requested sessions before publishing it without overwrite. Open refuses quarantined copies; there is no unquarantine method. This is a consistency primitive, not the encrypted backup/recovery ceremony required in Phase 3. A restart closes requested ledger records.

EmergencyDeny is a process-local latch that works when database writes fail. It is not durable revocation, remote cancellation or a substitute for stopping the service in a production emergency. Phase 2 has no service or forwarding path.

## Evidence and sources

See [Phase 2 report](docs/phase-2-report.md), [controller tests](internal/controller/store_test.go) and [domain contract](docs/controller-domain.md). Crash tests terminate subprocesses at transaction boundaries; they do not simulate hardware power loss or prove storage-controller flush behavior.

Primary references: [modernc driver](https://pkg.go.dev/modernc.org/sqlite@v1.58.0), [upstream source](https://gitlab.com/cznic/sqlite), [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html), [SQLite PRAGMA settings](https://www.sqlite.org/pragma.html), [SQLite VACUUM INTO](https://www.sqlite.org/lang_vacuum.html).
