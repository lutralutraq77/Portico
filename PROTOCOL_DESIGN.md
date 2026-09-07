# Protocol and API design

Status: Phase 0 candidate contract. No wire implementation exists. Q01 gates the reverse-stream adapter and Q02 gates browser/device binding.

## Established layers, Portico application messages
Use standard TLS 1.3 through reviewed libraries. TLS is designed for a reliable ordered stream; Portico must not implement key exchange, record encryption, nonce schemes or custom secure handshakes. Current RFC Editor material identifies RFC 9846 as the updated TLS 1.3 specification. [TLS 1.3](https://www.rfc-editor.org/info/rfc9846/).

Proposed carrier: HTTP/2 gRPC bidirectional streams initiated outbound by clients/connectors. gRPC supplies framed RPCs and streaming; Portico pairing, stream adapters, quotas and authorization state are still custom security-sensitive code requiring review. [gRPC concepts](https://grpc.io/docs/what-is-grpc/core-concepts/).

Outer TLS authenticates the ingress and enrolled infrastructure peers. Inner TLS between the client and connector protects resource transport from the relay. Do not replace it with claims in relay headers. For server-name validation, use an exact expected service name in a Portico-only certificate profile, plus typed immutable URI identity; name validation is explicit and does not require a global DNS change. Never disable chain/name verification as a shortcut.

## Transport options
| Option | Benefit | Cost / risk | Phase 0 decision |
|---|---|---|---|
| Embed OpenZiti fabric/SDK | Existing identity/service transport and dial/bind separation | Two policy/identity authorities, certificate enrollment integration, dependency footprint and revocation parity need proof | Serious reuse alternative; Q01 must compare before finalizing a custom adapter |
| Standard TLS over bounded gRPC reverse stream | One TCP ingress, mature crypto/RPC, Portico controls precise resource semantics | Custom reliable-stream adapter, cancellation and nested flow control; TCP head-of-line behavior | Preferred prototype candidate, not a production transport verdict |
| Generic HTTP CONNECT proxy | Standard tunnel semantics | Generic authority target is dangerous; outbound connector pairing still needed | No arbitrary CONNECT host:port API; only consider fixed server-derived routes |
| QUIC / HTTP/3 | Multiplexing with different loss behavior | UDP reachability, mobile/library testing, NAT profile and added exposed protocol | Defer; mature library only if added |
| Layer-3/WireGuard overlay | Mature encrypted IP transport | More routing/DNS/OS privilege surface than initial resource proxy needs | Not the initial model; no mesh or default route |

Embedding a mature fabric is not exempt from tests: its control plane defaults and direct APIs must not bypass Portico. Q01 records a re-evaluation gate rather than pretending a custom carrier has been reviewed.

## Endpoint classes
One public infrastructure listener may expose a fixed method allowlist:
- Pre-enrollment: small server-authenticated enrollment route, invitation + CSR only.
- Enrolled client: opaque connector tunnel and fixed restricted identity-service route.
- Connector: register availability, open reverse carrier streams, receive routing requests.
- Nothing maps an arbitrary hostname/port to a destination.

The identity service terminates end-to-end authentication for own-device lifecycle/catalog operations and exposes no management handlers. Gateway routing metadata does not establish principal identity. Connectors authenticate independently to the controller for hosting/session calls.

The dashboard/management API is private. A management resource does not remove its own device authentication or fresh hardware-key checks. The management connector cannot impersonate an admin by adding headers.

## Opening a resource stream
1. Client requests resource ID/current revision from its authenticated catalog.
2. Relay pairs only an admitted connector stream. Pair handles have short lifetime and one use but are not authorizing bearer tokens.
3. Inner mutual TLS proves expected connector and device identity. Client checks connector registry status through the restricted identity API before sending application bytes.
4. Inside inner TLS, client submits OpenResource(resource_id, revision). No destination override is accepted.
5. Connector sends AuthorizeSession to controller with verified client leaf identity, its own mTLS identity, resource revision and selected approved IP.
6. Controller validates live policy, commits session/audit intent and returns a bounded authorization. Connector dials only the exact approved tuple, then obtains a current activation confirmation before forwarding any application bytes.
7. Data uses a bounded ordered stream; every logical connection is separately authorized. Close/cancel propagates to the destination socket; it cannot leave an orphaned forwarding task.

Certificate verification is not automatically revocation checking; live registry status is required. Initially disable TLS resumption and early data on authenticated Portico endpoints to avoid hidden reauthentication bypass. Re-enabling resumption later requires explicit tests of status checking and identity binding on resumed handshakes.

## Message and resource limits
Proposed starting limits: enrollment body 16 KiB, ordinary control request 64 KiB, data chunk 32 KiB, per-stream buffered payload 256 KiB, handshake/activation deadline 5 seconds. Exact per-device/connector concurrency and aggregate memory budgets need Q01 measurements.

Use generated protobuf or reviewed JSON decoders; unknown security-critical enums/fields are rejected. Public JSON mutation handlers reject unknown fields and duplicate keys, use explicit DTOs and never mass-assign domain objects. Preserve limits through decompression or disable compression on sensitive methods. No unlimited messages, recursion, queues, goroutines or retry loops.

Treat HTTP/2 reset floods, slow reads, abandoned streams, malformed CSRs, duplicate messages and reconnect storms as adversarial. cancellation must unblock readers/writers and release sockets. No TCP half-close behavior is promised until end-to-end stream tests define it; preserve graceful completion where compatible with hard revocation.

## Versioned API sketch
Names are proposed design, not implemented routes.

| Surface | Examples | Authorization |
|---|---|---|
| Restricted /api/v1/enrollment | redeem invitation, retrieve own issued public certificate by bound attempt | Invitation scope + CSR proof; no generic CA sign |
| Restricted /api/v1/device | own certificate renewal, own allowed catalog | Current device mTLS and live authority |
| Private /api/v1/admin | users/devices/resources/grants/connectors; revoke; session terminate | Active admin device/authority and operation-specific permission |
| Private /api/v1/admin/operations | preview, create challenge, confirm mutation | Exact immutable operation; fresh WebAuthn for sensitive actions |
| Private /api/v1/admin/security | factors, CA/recovery settings, backups and updates | Explicit sensitive-operation handlers |
| Connector RPC v1 | hosting registration, authorize/activate/renew/close | Connector mTLS and matching HostBinding/session owner |
| Issuer internal | issue only approved CSR/profile/expiry | Registration authority only |

Lists contain scoped metadata, never invitation plaintext. Failed resource lookup and unauthorized lookup use indistinguishable public responses. Errors carry stable reason enums and a correlation ID; internal stack/secret details stay out of responses and ordinary logs.

## Browser/API defenses
Use server-side session state bound to verified device identity. Secure HttpOnly SameSite cookies are browser transport controls, not a replacement for the certificate factor. Require CSRF tokens and strict Origin/Host checks on relevant requests. Disable wildcard CORS, framing and unnecessary remote scripts. Set no-store on sensitive responses; redact before serialization; keep secrets out of URLs and browser persistence.

UI and direct API invoke the same authorization handlers. No frontend-only step-up, masked HTML secret, generic admin-ish check or hidden alternate endpoint. Capture the exact operation approved by the user; changed resource revision or policy requires a new preview.

Compatibility: major version and required capabilities are explicit. Unknown required security capability denies. Use bounded retry with idempotent operation IDs bound to actor and immutable input; do not retry an ambiguous permission increase as a new operation.

## Proof
PROTO-01–05, ADMIN-07–08, SECRET-01–04 and AUTHZ-08 are required. CTRL-07/08/14/18 cover trust, failure and recovery. This document is a security contract for a future implementation, not a new encryption protocol.
