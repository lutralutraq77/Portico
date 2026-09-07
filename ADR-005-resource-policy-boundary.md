# ADR-005: Authoritative resource policy and hardware-approved previews

Status: accepted for the Phase 4 software boundary. Data-plane and platform acceptance remain open.

## Decision

Use one online controller decision for an exact enrolled device, connector, resource revision, Grant and HostBinding. The connector supplies the public client certificate it verified during inner TLS and a resource ID/revision. It cannot submit an address, port, username, grant ID or enabled flag. The controller derives the destination and expiry from committed authority, verifies both certificate profiles against pinned issuers and checks the live registry on every call, including reused TLS connections.

The controller does not prove a client's private-key possession from certificate bytes. That proof belongs to the connector's inner TLS handshake. A malicious connector can lie about client metadata and already controls the sockets on its workload host; independent workload segmentation remains required. It cannot change the controller's stored destination, host another connector's resource or enter administrator APIs through this interface.

No matching grant, multiple matching grants/bindings, a stale revision, disabled authority, a management resource, unknown version, protected destination, expired deadline or storage failure denies. Only canonical literal IPs and one TCP port are currently supported. Deployment supplies explicit protected network prefixes; built-in local/metadata address exclusions still apply. Hostname and management-resource support need their separate designs and qualification.

## Authorization and activation

Authorization creates an audited session plus a bounded permission record. Activation and renewal require the same connector certificate and exact next sequence, then repeat the live predicate against the original device certificate and original Grant/HostBinding. They cannot switch to a replacement grant, extend the absolute session lifetime or revive a closed session. The configuration hash binds trust pins, destination exclusions and limits. Changed configuration invalidates old permissions.

Global, per-device and per-connector quotas are checked in the same SQLite transaction as allocation. The session expires at the earliest device authority, grant, hosting, client certificate, connector certificate or configured session deadline. Session lifetime is capped at one hour, lease lifetime at fifteen seconds, activation at five seconds within its lease. These are bounds on controller responses; no remote socket timing guarantee is claimed by this component.

Schema 4 records cancellation targets transactionally when a session closes. Delivery, acknowledgments, request-start-anchored connector timers, suspend handling and measured socket closure remain Phase 5/platform work. Q05 remains open; the numeric connected/partition targets have not been accepted or qualified. Restart closes existing sessions before the store becomes available. Quarantined snapshots close sessions and remove policy previews as well as credential authority.

## Immutable administrator preview

The server creates the exact proposed Resource, Grant or HostBinding and a display preview containing effective user/device, connector, address, port, protocol, revision and deadline as applicable. Endpoint revisions show both previous and proposed endpoints. The server chooses immutable IDs and enabled/application flags. Creating a resource or HostBinding never implicitly creates a device grant. A new revision disables old grants/hosting and closes old sessions.

The five-minute preview is bound to the authenticated administrator device, user, certificate, configuration hash and authority revision. A digest covers both stored operation and display. The two-minute WebAuthn challenge additionally binds the digest and preview ID. At least two enabled, tested factors must exist before policy approval starts. One fresh required-UV assertion from the reviewed hardware policy completes the exact operation; the two-key inventory is for independent recovery, not a two-signature quorum. Physical independence still needs real hardware evidence.

Approval, signature counter, preview consumption, policy change and audit commit atomically. A wrong completion endpoint, changed authority, expired challenge, changed content or failed audit leaves the mutation unapplied. Concurrent submissions consume the approval exactly once. Session/audit traffic does not invalidate a preview, while changes to authority do.

Schema 4 therefore separates `policy_meta.revision` from the audit event generation. Material authority mutations increment it; WebAuthn counter updates for already-tested factors do not. Migration starts it at one so existing administrators can approve immediately, and deletes ceremonies bound to the earlier generation scheme. Migration rollback preserves the complete previous schema, factors and audit history.

## Private HTTP boundary

`PolicyEngine.NewHTTPServer` owns TLS policy and the actual `tls.Conn` context. It exposes separate device, connector and administrator allowlists, requires TLS 1.3 and checks current registry authority per request. It accepts only explicitly supplied loopback listeners during development. No public listener, bootstrap route, browser bridge or arbitrary CONNECT target is added.

Requests use POST, exact Host, application/json, no query or content encoding, a 64 KiB body limit and finite HTTP deadlines. Administrative requests require the verifier's exact HTTPS Origin. The standard JSON parser is wrapped with duplicate/case-alias, unknown-field, nesting, member-count and trailing-input rejection. DTOs prevent domain-object mass assignment. Errors are fixed and do not echo request data; responses have no-store and nosniff headers. Browser CSRF/session/IPC design is still a Phase 7 gate; Origin alone does not establish local-user isolation.

## Verification and limits

The tests in internal/controller/policy*_test.go exercise real fixture issuance, real mutual TLS and signed virtual WebAuthn responses, exact authorization, one-use approvals, API misuse, stale authority, quota races, audit rollback, schema migration and quarantine. internal/wire/json_test.go adds parser adversarial and fuzz coverage. The shared Windows/Linux check suite and isolated Linux VM execute these packages.

These component tests do not satisfy the full AUTHZ, CONN, SESSION or ADMIN acceptance cases without their actual sockets, malicious clients, browsers, OS boundaries and physical keys. The canonical 91-case manifest keeps those cases planned until their complete scenarios are observed. See [delivery status](docs/delivery-status.md) and [policy API](docs/policy-api.md).
