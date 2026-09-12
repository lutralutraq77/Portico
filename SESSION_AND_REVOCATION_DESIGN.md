# Sessions, expiry and revocation

Status: end-to-end semantics and test targets; no qualified universal socket-termination guarantee. Phase 4 implements controller authorization/activation/renewal, quotas, deadlines and durable cancellation targets. Phase 5 adds authenticated bounded long polling, repeat-until-acknowledged delivery and immutable closure reports; see the [policy API](docs/policy-api.md). A development [workload consumer](docs/workload-runtime.md) now composes actual inner TLS, exact TCP forwarding, request-start timers and closure after worker completion. Isolated fixture measurements do not qualify physical suspend, hostile load or deployed egress isolation; a report alone cannot prove closure. [ADR-005](ADR-005-resource-policy-boundary.md) describes the policy boundary.

## Separate lifetimes
| Lifetime | Proposed default / rule |
|---|---|
| Ordinary certificate | 24 hours; administrator can choose 2 hours, 1 day, 7 days, 30 days/custom; configurable initial ceiling 30 days |
| Device enrollment authority | Explicit absolute administrator-selected expiry; renewal never extends it |
| Administrator certificate / authority | 1 hour by default, independently configurable cap; scheduled/longer policy requires review |
| Resource grant | Explicit start/expiry; never extends device authority or certificate |
| Data session | Maximum 1 hour, idle timeout 15 minutes, shortened by every applicable deadline |
| Admin browser session | 15 minutes idle, 1 hour absolute, bounded by admin certificate and authority |
| Step-up challenge | 2 minutes, single use for one exact operation, not a reusable elevation window |
| Data lease | At most 15 seconds; refresh approximately every 5 seconds |
| Activation allowance | At most 5 seconds within the lease; never activate late |

Values need load/mobile validation. Configuration may tighten them. Raising the 15-second lease ceiling changes a security guarantee and requires a reviewed design change and requalification.

Effective session end is the minimum of client and connector certificate expiry, device authority, grant and HostBinding expiry, absolute session end, idle deadline and lease deadline. A new certificate does not extend an existing session: reconnect and reauthorize.

## State machine
Requested → Authorized → Activating → Active → Closing → Closed.
Pre-active states may become Denied or Expired. Terminal states never reactivate.

Authorization and audit intent commit together. At activation the connector rechecks its resource snapshot and obtains current controller confirmation before forwarding application bytes. Destination dial attempts may occur during concurrent revocation; remaining races follow the bounded cancellation rule.

## Meaning of immediate revocation
On authoritative commit, revoke/disable the target, advance generation and record affected sessions. New authorizations and renewals after that commit deny. Push ordered cancellation to relevant connectors, relay and management sessions; close destination sockets and streams.

Record peer acknowledgments separately. UI reports “revoked; termination pending” until acknowledgment or safe lease-expiry evidence; a database write alone does not prove every socket closed.

Connected acceptance target: socket closure within **2 seconds** of commit.
Partition acceptance target: no forwarding more than **15 seconds** after the relevant renewal request began, plus at most **1 second** measured scheduling tolerance in qualified environments.

These are engineering targets, not universal hard real-time claims. In-flight packets, already queued kernel bytes and work already performed cannot be recalled. On resume, check expiration before forwarding. A compromised connector can ignore its timers; independent egress controls contain its reach.

The prompt's “immediate” requirement cannot mean instantaneous global termination during a partition. Q05 records this explicit constraint. No offline-allow fallback is proposed.

## Lease safety
An authenticated connector can refresh only its own sessions. Every refresh re-evaluates the full live predicate and binds session ID, connector, certificate serials, resource revision, policy generation, deadlines and monotonic sequence.

The connector anchors the deadline to monotonic request-send time, never response receipt. Reject delayed, duplicate, out-of-order and expired responses. Conservatively shorten validity for clock uncertainty. Monotonic time must include suspend, or resume detection must invalidate all sessions. Leases never survive restart.

UTC clocks govern certificate/policy validity. Proposed unhealthy-clock threshold: uncertainty greater than 30 seconds. No skew allowance extends expiry. Use conservative early stopping; backward steps, restore, restart or unexplained time state invalidate local authority pending online resynchronization. Timezone changes never extend existing sessions.

## Outages
New sessions require a fresh successful authoritative check. Controller, certificate status or required audit/session storage failure denies permits/renewals. Existing sessions stop by lease expiry. Relay loss closes carried streams. Connector restart drops all sockets; reconnect requires fresh TLS and authorization.

Heartbeat connectivity is not proof of fresh policy. Event sequence gaps trigger resynchronization. No offline allow-list mode exists in MVP.

## Operation semantics
Terminate-session tombstones and closes one ID; a still-authorized device may create a new session. Revoke-device disables all that device's credentials and sessions. Revoke-grant, disable-resource and disable-connector cancel their dependent streams. Revoke-admin closes browser sessions and outstanding challenges.

“Replace lost/stolen credential” atomically records the new approved credential and revokes selected old credentials, then cancels their sessions. Merely issuing a certificate does not revoke anything. Planned rotation can have an explicit short overlap; it is a different operation from compromise replacement.

Emergency deny/terminate may use a currently authenticated authorized administrator without additional hardware touch. Permission increases and protection changes require fresh step-up. Revoking the last admin must be deliberate, with visible consequences; independent physical recovery remains available.

## Schedule and daylight saving
Store recurrence, IANA timezone, timezone database version and computed UTC intervals. “Every day at 12:00 Europe/London” means 11:00 UTC during summer and 12:00 UTC during winter. Compute calendar occurrences, not repeated 24-hour additions.

For an ambiguous wall time choose the earlier UTC occurrence. For a nonexistent time choose the first valid instant after the gap. Preview upcoming occurrences before approval. An elapsed maximum lifetime still caps an interval, potentially expiring earlier; show this explicitly.

Renewal window is configurable (proposal: final 15 minutes of a 1-hour interval). A fresh hardware approval authorizes only the specified next interval, never unlimited future renewals. A future-not-before certificate remains inactive until its approved start, with bounded overlap. Failed/missed renewal closes remote administration. Another valid admin device or physical console recovers it; expired certificates are not remote renewal credentials.

## Proof
SESSION-01–06 require socket/packet observation, controlled clocks, event loss, delayed renewals, suspend and restart. ADMIN-02/03 cover certificate theft and calendar renewal. A policy unit test alone does not prove termination.
