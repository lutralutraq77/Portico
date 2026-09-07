# Controller domain implementation

Phase 2 implements users, devices, connectors, issuer/certificate metadata, immutable endpoint revisions, exact device grants, independent HostBindings, requested session records and audit events in internal/controller.

## Trust boundary

Store.Update and its Tx methods are trusted in-process storage operations. They do not verify TLS identities, hardware approval, enrollment or administrator roles. An actor UUID or approval reference is metadata, never authentication evidence. No listener directly exposes these methods. Phase 3 adds verified certificate/admin entry points and Phase 4 adds [private policy APIs](policy-api.md) that authenticate before invoking domain transactions.

The version-only executable reports Phase 4; PKI/enrollment additions are described in [the integration report](phase-3-integration-report.md). Application state is exercised through domain, real TLS and policy API tests; no CLI command starts a controller or connector service.

## Rules enforced now

- IDs use UUID generation and canonical validation; names do not determine identity.
- Device ownership uses a composite foreign key. A future device inherits no grant.
- Endpoint changes require the expected current revision, create a new revision, disable old grants/HostBindings and close dependent requested sessions.
- Display-only resource rename preserves the endpoint revision.
- Literal IPs and one TCP port are supported; hostnames, ranges, zones, URLs, wildcard destinations and unsafe local address classes are rejected. Deployment-specific management-address exclusions are still required before real dialing.
- Certificate profiles bind exactly one device or connector; issuer/serial and leaf fingerprint are unique. Registering replacement metadata does not revoke an old certificate.
- Session recording checks exact identities/revisions, enabled states, independent host/dial permissions and bounded deadlines. Management resources cannot produce requested sessions until admin authority is implemented.
- Domain requested records can only end denied, expired or closed. Schema 4 adds a separate authorized/active permission record with sequences, configuration binding and deadlines. It cannot forward traffic itself.
- Disable operations conservatively close all requested records; restart also closes them. Later targeted cancellation may narrow the affected set while preserving required denial.
- State and audit commit together. Storage errors and ignored mutation errors roll back. EmergencyDeny latches process-local denial independently of storage.

All security IDs and references in audit output are allowlisted; display names, tokens, addresses, certificate contents and arbitrary request bodies are excluded. Hash checkpoints detect gaps/reordering/tampering relative to retained evidence; they do not protect against a controller owner rewriting local state and its checkpoint.

## Persistence and limitations

See [storage decision](../ADR-002-controller-storage.md). Tests use isolated databases; no production database is created. One process owns a local database directory. Filesystem ownership/ACLs, actual disk encryption, remote audit transport, authenticated mutation handlers, clock-health integration and physical recovery remain deployment/application work.

The [runtime acceptance manifest](../tests/acceptance/manifest.json) distinguishes the implemented audit crash case from partial component evidence for other cases. Passing a domain test never substitutes for destination socket counters or certificate handshakes.
