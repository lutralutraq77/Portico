# enrollment

The canonical design is [PKI_DESIGN.md](../PKI_DESIGN.md).

Durable ordinary enrollment includes hashed invitations, attempt/CSR binding, one issuer invocation, registered public results and real TLS activation. The [restricted issuer](issuer.md) now implements the provider against Smallstep. Administrator-approved ordinary invitations can commit with their one-use WebAuthn assertion and audit event. Administrator bootstrap certificates still enter through a trusted local owner operation; no public registration/reset endpoint exists. See [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) and [current integration evidence](phase-3-integration-report.md).

## Verified ordinary enrollment transport components

The development libraries now expose separate HTTPS redemption and activation
servers and an ordinary enrollment client. The servers accept supplied loopback
listeners only. The [development Linux enrollment command](enrollment-command.md)
now composes these components with encrypted local key/attempt state and a
separate inherited secret pipe. An installed enrollment service and interactive
launcher remain required.

The caller obtains the invitation secret, expected principal and certificate
deadline, issuer/root trust, and both endpoints' server roots and SPKI pins
through an approved trusted channel. Server authentication finishes before the
client sends the invitation. Discovery and trust on first use do not establish
trust. The caller owns the signer and must durably retain its key and attempt ID
before sending a request. The transport library does not generate or persist
that key/attempt; the separate state/command layer enforces that ordering.

1. `POST /api/v1/enrollment/redeem` carries only `Version`, `InvitationID`,
   `Secret`, `AttemptID` and a base64 `CSR`. Version is 1. The CSR proves local
   key possession and must contain no subject, SAN or extension claims.
2. The redemption server checks its configured issuer/profile against the
   invitation before reservation. Identity and lifetime come from the controller
   record. It reserves one attempt/public key, invokes the restricted issuer at
   most once and registers the exact issued certificate before returning it.
3. The client verifies the returned invitation/attempt, typed certificate trust,
   principal, exact approved expiry and local public key. It reconstructs the
   normalized certificate chain with its local signer.
4. On a fresh TLS 1.3 connection, `POST /api/v1/enrollment/activate` carries
   `Version` and `InvitationID`. The activation server authenticates the actual
   client TLS certificate against the live pending/active registry and requires
   that it belongs to this invitation. Its configuration cannot carry an issuer
   provider. Success returns the exact version and invitation ID.

The redemption response contains `Version`, `InvitationID`, `AttemptID` and
base64 `CertificateDER`. Activation cannot be proved by a public certificate
in a body/header, a proxy assertion, or a caller-supplied TLS connection state.
Administrator profiles and invitation creation are absent from both endpoints.

An identical attempt using the same key may retrieve the same public result;
re-signing the empty CSR does not allocate another signing attempt. A concurrent
request while issuance is underway may fail and be retried explicitly. A lost
issuer response leaves the durable state ambiguous: the client cannot trigger
another signing call. A trusted operator may reconcile the issuer's public
receipt, or revoke the attempt and approve a new invitation. This transport adds
no remote reconciliation, reset, renewal or rekey route. Revocation and current
authority are checked again on later retrieval and activation.

Requests/responses are bounded to 16 KiB of strict JSON. The server has explicit
connection (at most 32) and request (at most 8) admission limits and deadlines of
at most five seconds. Excess connections are closed before TLS admission and
excess requests are rejected without an application queue. The client also has
bounded request admission. Redirects, environment proxies, compressed responses,
TLS session resumption and connection reuse are disabled. The ingress accepts
only its configured host, route, method and JSON content type; browser origins,
cookies and authorization headers are rejected. Protocol denials use a fixed
error body; TLS or HTTP parser failures can close the connection earlier.

Closing the server cancels its root context and waits for HTTP shutdown within
the caller's deadline. Providers must honor cancellation. An ambiguous cancelled
signing operation remains in `issuing`; cancellation does not release it for a
new signing attempt. The client closes in-flight requests and joins their
network operations. Buffered plaintext in the process cannot be guaranteed
erased by Go's garbage collector; the implementation clears owned mutable token
buffers but does not claim memory-forensic secrecy. Request-body reads and
erasure share a lock because HTTP transport cleanup can continue after an error
returns. Closing a body makes subsequent reads return EOF and creates no replay
copy of the invitation.

Actual HTTPS component tests and a composed restricted Smallstep workflow for
both ordinary profiles passed on source a1e284ca09b71c7acedb73fb16e4fd5bf222ee6a.
The [enrollment report](phase-6-enrollment-report.md) records the complete hosted
Linux guest, native Windows/Linux quality checks, exact source tree and archived
evidence. Later local-state changes need separate verification. Full platform
enrollment and integration of encrypted state into resource access, administrator
hardware, installed services, production custody and all remaining acceptance
gates remain open.
