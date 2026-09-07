# Resource and authorization model

Status: normative domain contract. Phase 2 implements local schema and trusted domain transactions; authenticated policy enforcement and networking remain later phases. See docs/controller-domain.md.

## Entities
Security IDs are immutable, deployment-scoped random identifiers generated using an established UUID library and OS randomness. Display names are mutable and non-authoritative. Deleted IDs are never reused.

| Entity | Minimum fields |
|---|---|
| User | id, display_name, enabled, created_at, disabled_at; no email required |
| Device | id, owner_user_id, platform, enabled, authorization_not_after, credential references, enrollment and last-seen metadata |
| Credential | issuer_id + serial, device/service ID, SPKI fingerprint, exact leaf fingerprint, profile, validity, revocation state/reason/time |
| Connector | id, name, enabled, service credential, version/capabilities, last_seen |
| Resource | id, revision, kind (application or management), name, connector_id, address type/value, one port, transport, enabled, approved concrete IP set, audit metadata |
| HostBinding | id, connector_id, resource_id/revision, enabled, valid_from/until |
| Grant | id, user_id, explicit device_id, resource_id/revision, valid_from/until, enabled, creator and approval reference |
| Session | id, user/device/credential/connector/resource/grant references, selected IP/port/protocol, deadlines, lease sequence, state |
| Invitation | id, hashed verifier, target/profile/lifetime scope, expiry, redemption state and CSR binding |
| AdminAuthority | admin device ID, valid_from/until, permissions, credential epoch |
| AuditEvent | id, sequence, UTC time, actor IDs, action, target IDs, result/reason enum, correlation ID, redacted change reference |

Use foreign keys and uniqueness constraints. Endpoint or connector changes create a new resource revision. Existing grants and HostBindings do not silently transfer. Display-only renames preserve endpoint revision. Deletion disables first, terminates sessions and retains necessary tombstones.

## Simple UI and effective preview
Ask for name, connector, destination and port; default protocol TCP. Unsupported protocols are rejected, not downgraded. Advanced controls expose expiry and DNS approval, never a hidden all-ports permission.

Selecting a user requires selecting their currently enrolled devices. MVP stores explicit device grants; future devices inherit nothing. Group/future-device semantics need a later design decision.

The server previews: Alice / Pixel 9 → Jellyfin → Home Server → 192.168.50.10:8096/TCP, resource revision and expiry. Show affected identities and address changes. SSH/proxy resources may permit application-mediated onward access. Commit uses optimistic version checks and the exact server-side preview reference; changed inputs require a new preview and fresh hardware approval.

## Authorization predicate
Permit a new stream only when every condition holds at one authoritative decision point:
1. TLS proves a registered active leaf key in the current deployment and expected device profile.
2. User, device, credential and issuer are enabled, unrevoked and time-valid.
3. Resource is enabled and requested revision is current.
4. Authenticated connector ID/certificate is active and matches the resource.
5. A current HostBinding permits that connector to host that resource revision.
6. A current Grant matches the user's immutable ID, exact device and resource revision.
7. Concrete selected IP is approved; the single port/protocol exactly matches.
8. Policy/revocation state, compatibility, clocks and required audit/session storage are healthy.
9. All quotas and destination checks pass and effective remaining lifetime is positive.
10. A management-kind resource additionally requires an active administrator device profile and AdminAuthority. Ordinary device grants cannot confer this role; changing resource kind is a sensitive operation.

No match, ambiguity, unknown protocol, stale revision or exception means deny. Responses must not reveal other users' resources. Device ownership comes from the registry, never a caller's username. Connector ID comes from its controller mTLS connection.

A malicious connector may falsify reported client metadata; it already controls its workload-side socket boundary. The design does not claim to stop that connector exposing its own reachable workloads. It must still be unable to change policy, acquire admin credentials or host another connector's resources.

## Address validation
Use standard parsers. Accept a literal IPv4/IPv6 address or one explicit hostname. Reject URLs, embedded credentials/ports, wildcards, CIDRs, ranges, port zero, invalid integer ports, ambiguous IP encodings and IPv6 zone IDs. Normalize IPv4-mapped IPv6 consistently.

Default exclusions: unspecified, multicast, broadcast, loopback, link-local and metadata-service addresses. Deployment configuration also identifies controller, issuer, relay-management, Docker API and router-management destinations. Private RFC1918/ULA space is not automatically safe.

Host-local SSH may be an explicit reviewed resource; authorizing its one port must not remove exclusions generally. A port number alone cannot identify a management service on a nonstandard port. Workload segmentation remains essential.

Literal addresses are the baseline. Hostnames require the pinned-answer policy in [DNS design](DNS_DESIGN.md): a new A/AAAA answer pauses access until an administrator reviews and approves a new resource revision.

## Races and recovery
State mutations advance policy generation and record cancellation targets transactionally. A stream authorized just before revocation counts as existing and is cancelled under [session rules](SESSION_AND_REVOCATION_DESIGN.md). Activation rechecks current policy. Network I/O is not atomic with a database transaction; remaining races are bounded by cancellation/leases.

Session IDs are correlation handles, never reusable bearer capabilities. TLS channel reuse does not avoid per-stream checks. Restore a changed resource through a reviewed grant/HostBinding, never an old cached revision.

AUTHZ-01–08, CONN-01–04 and DNS-02–04 must observe actual destination socket counters, not only API denial. CTRL-02/03/10 describe threat, trust, failure and recovery.
