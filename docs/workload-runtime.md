# Connector workload runtime

The internal/workload package composes the Phase 5 carrier, inner TLS and online policy client. It is a development library; the main CLI still exposes help/version only. Service configuration, operating-system clock-health providers, independent egress isolation and platform qualification remain required. The current verification checkpoint is recorded separately in the [workload progress report](phase-5-workload-report.md).

## Opening one resource

The caller supplies one paired carrier stream, a context that owns its lifetime and a selected resource revision. The device completes the standard inner TLS handshake for the exact connector DNS identity, verifies the actual peer certificate and obtains a fresh controller check for that certificate and resource. Its bounded open message contains only protocol version, resource UUID and revision; it cannot carry an address, port, arbitrary hostname or bearer permit.

The connector authenticates the actual inner device certificate and applies shared process/per-device connection limits. It requires an exact match between its independently supplied local destination configuration and a fresh hosting snapshot. It submits the actual verified device leaf for online authorization, then dials only the configured literal TCP address and port. After the dial it rechecks hosting and obtains activation before sending readiness or starting application forwarding. A failed activation closes the destination without forwarding application bytes. A destination connection can occur during concurrent revocation after authorization; this does not eliminate the documented bounded termination race.

Destination configuration rejects loopback, link-local, unspecified, multicast, IPv4-mapped IPv6, zone identifiers, noncanonical literals, unsupported protocols and protected network prefixes. Local configuration is trusted input and must be explicitly updated when the approved tuple changes. It does not substitute for independent network enforcement around a compromised connector.

## Live authority and timing

Each connection uses bounded 32 KiB forwarding buffers, a configurable idle ceiling of fifteen minutes and an absolute ceiling of one hour. Controller leases are at most fifteen seconds; initial activation must occur within five seconds and within the existing lease. Both endpoints check current authority before I/O and have independent 25 ms supervisors that close blocked streams when authority expires. Renewal/control calls do not hold the session lock or suspend the supervisor.

Returned lifetime is anchored to the local request-start CLOCK_BOOTTIME/Windows interrupt-time sample. Transport delay and clock uncertainty shorten it. UTC bounds independently cap certificate, hosting and session expiry. Subsequent authorizations pin the original session, actual principals, certificate identifiers, resource revision/address/port/protocol and absolute end; sequence must advance exactly once and policy revision cannot decrease. Fresh replies cannot revive a stopped or expired session. The client also rechecks the actual connector and rejects a regressed policy revision.

ClockHealth is a required trusted, current, nonblocking local health estimate. Missing/stale/error estimates, native-clock failures, backward time, unexpected elapsed/UTC disagreement and excessive sampling delay latch the runtime closed. A [read-only Linux kernel health provider](connector-clock.md) is implemented; workload tests still provide explicit fixture uncertainty. Deployment time-service and physical suspend/hibernate qualification remain pending. The conservative fail-closed behavior can end a session early under adverse scheduling or clock conditions.

## Closing and receipts

Revocation, failed online renewal, lost control/carrier, expiry or caller shutdown closes both owned handles. Stop is synchronized: concurrent callers wait until actual Close calls return. Application DATA/FIN/ACK frames remain inside the authenticated inner TLS stream; DATA is at most 32 KiB and FIN/ACK have no payload. TCP half-close preserves the reverse direction. The connector waits for a FIN acknowledgment, sent only after the peer consumes preceding application data, before closing the carrier gracefully. A successful local TLS Write is insufficient because the carrier transports bytes asynchronously. Forced shutdown closes the raw carrier directly and never waits for the graceful acknowledgment.

The framing adds one bounded receive buffer and one single-use acknowledgment worker per connection. Duplicate/malformed control frames, data after FIN and acknowledgment before a sent FIN terminate the stream. Both framing workers are included in the local join barrier. No acknowledgment is a new permit or an independent claim about a compromised peer's behavior.

The connector keeps a bounded ownership record for each controller session, including pending receipts. It selects only those IDs in cancellation polls and never acknowledges unknown records left by another runtime. A receipt is sent only after forwarding/monitoring workers join and the carrier's Done signal confirms its workers have joined. A carrier join timeout prevents acknowledgment and retains the pending record; capacity exhaustion denies new sessions instead of discarding closure obligations. Closure reports remain authenticated connector testimony, not independent proof against a compromised connector.

## Isolated destination tests

The Linux harness adds 192.0.2.10/32 to the NIC-less guest's loopback while preserving localhost. Before opening the fixture destination, tests require Linux, an explicit guest marker/environment flag and the absence of any non-loopback network interface. No host route, host destination listener or LAN dial is added. Actual carrier TLS/gRPC, inner TLS, control HTTPS and destination TCP execute inside the guest.

The WorkloadOnly harness mode runs the focused clock/workload/connector integration tests and emits PORTICO_LINUX_WORKLOAD_PASS. It cannot emit the complete-suite success marker. Windows and ordinary hosted unit runs explicitly skip guest-only destination cases; their race/scanner results must be paired with separate guest evidence.

The canonical acceptance manifest still contains 91 complete runtime scenarios. These component and fixture tests do not promote the remaining planned cases or resolve Q05's requested timing acceptance.
