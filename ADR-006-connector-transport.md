# ADR-006: Standard TLS over a bounded gRPC carrier

Status: accepted for the isolated Phase 5 prototype design. Production, hostile-load, mobile and independent security qualification remain required.

## Comparison and decision

OpenZiti is a serious reuse alternative: its Go SDK provides authenticated service dialing, hosting, router connections and lifecycle handling. The inspected interface and implementation also maintain identity/service state, cached services and sessionless as well as legacy session-based connection paths. [SDK source, pinned revision 83e8076a438ec3084ad5634d29bccc4ad86103a5](https://github.com/openziti/sdk-golang/blob/83e8076a438ec3084ad5634d29bccc4ad86103a5/ziti/ziti.go). Its dependency graph includes dedicated controller API, identity, channel and transport packages. [Inspected module manifest](https://github.com/openziti/sdk-golang/blob/83e8076a438ec3084ad5634d29bccc4ad86103a5/go.mod).

Inference for this application: embedding that fabric would require synchronizing a second identity/service authority with Portico's exact device/resource revisions, grant expiries and administrator approval rules. Using it only as an opaque carrier would still require Portico's inner authentication, online policy and socket leases. This is an integration tradeoff, not a claim that OpenZiti is insecure or cannot implement the model. No OpenZiti performance benchmark or complete dependency/security audit was performed.

Choose standard Go TLS 1.3 over generated gRPC bidirectional carrier streams for the prototype. gRPC provides framing and streaming flow control, including blocking when a receiver cannot keep up; an application write is not proof of delivery. [Flow control](https://grpc.io/docs/guides/flow-control/). It does not forcibly stop arbitrary handler work, so Portico must propagate cancellation into every local stream/socket operation and release resources. [Cancellation](https://grpc.io/docs/guides/cancellation/). Every finite operation needs an explicit deadline; gRPC does not supply a useful application deadline by default. [Deadlines](https://grpc.io/docs/guides/deadlines/).

Keep the carrier behind a standard net.Conn boundary so an alternative mature fabric can be evaluated if this composition fails its tests. The custom code is pairing, bounded byte adaptation and lifecycle/policy enforcement. There is no custom encryption, key exchange, packet reliability protocol or generic CONNECT destination.

## Prototype contract

- One logical TCP connection uses one paired bidirectional stream. Connectors initiate bounded outbound waiting slots; clients request a connector identified by immutable ID. Relay pairing is not resource authorization.
- The relay authenticates admitted infrastructure/client peers independently and sees only inner ciphertext. It cannot select a destination tuple, mint grants or supply administrator identity. Any fixed identity-service route has a separate allowlist and destination.
- Generated messages have explicit version/type checks and strict bounds. Start with at most 32 KiB payload chunks, bounded queues/windows and explicit per-peer/global stream limits. Slow readers, abandoned slots, unknown fields/types, resets and cancellation must be tested. No unlimited reconnect/retry or goroutine queue is allowed.
- Inner mutual TLS verifies the expected connector and the enrolled device profile before any resource request. The client performs a live controller check of the actual connector certificate. The connector submits the actual verified device leaf to the controller and obtains authorization for the exact stored resource revision.
- The connector compares the returned tuple with its current local hosting snapshot, dials exactly that tuple and obtains activation before copying application bytes. Each logical connection requires a separate authorization even when carrier channels are reused.
- A connector tracks actual stream and destination handles. Durable cancellation targets are delivered repeatedly until acknowledged after local closure. Authorization/activation/renewal failure, cancellation, connection loss, local timeout or restart closes both sides. No orphan forwarding routine may survive a handler exit.
- Lease validity is anchored to monotonic request start and conservatively shortened for response delay and uncertainty. Suspend/resume must invalidate authority unless the platform clock includes suspend and passes qualification. A UTC timestamp from the controller is insufficient by itself.

Q05's numeric termination targets remain a separate user decision and runtime evidence gate. The prototype may enforce tighter limits but cannot claim that measured bounded termination is already accepted as the prompt's meaning of immediate revocation.

## Connector TLS name profile

Phase 3 connector leaves already require both clientAuth and serverAuth, but their URI-only SAN does not support the standard TLS client's DNS-name verification. Extend only the connector profile with exactly one deterministic DNS SAN: `<connector-uuid>.<deployment-uuid>.connector.portico.invalid`. The registration authority derives it from approved IDs, signs it with the exact URI, and both issuer and client verify it. The subject stays empty and the SAN extension critical; other profiles retain URI-only SANs. Unexpected or duplicate names remain rejected.

The name is a private certificate identity, not a resolver entry, route, public hostname or new global trust root. The client supplies it as the expected TLS ServerName on the already paired byte stream, keeps normal chain/name verification enabled, and additionally verifies the typed URI/profile, pinned intermediate and live registry. Device/connector private keys stay local. No InsecureSkipVerify fallback is introduced.

This is an explicit development connector-profile change. Older URI-only connector leaves will fail strict validation and require reissuance; they are not accepted through a compatibility bypass. The issuer's durable profile binding must distinguish the revised connector profile before serving it. Production migration remains unqualified.

## Required proof

Before claiming Phase 5 completion, execute CONN-01–04, PROTO-01–05 and SESSION-01–06 as complete scenarios, plus AUTHZ socket-isolation tests. Observe destination connection counts and closure, inner plaintext confidentiality, wrong pairing/certificates, stale state, controller outages, delayed responses, duplicate messages, simultaneous close, blocked send/receive, restart and bounded memory under hostile load. Cross-platform suspension and application qualification remain subsequent gates.

Q01 is resolved only for this prototype design. Q02/Q03 still gate production browser/native administration and real hardware claims. The owner explicitly allowed isolated test fixtures while key models and hostname are undecided; that permits independent connector software tests without inventing physical evidence.
