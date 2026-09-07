# Phase 0 consistency review

Date: 7 September 2026
Status: historical Phase 0 record. Phase 1 was authorized afterward; current evidence is in docs/phase-1-report.md. This review provides no runtime test, independent audit or production approval.

## Deliverable checks
- All 17 requested design documents are present at the package root.
- Supporting documents cover protocol/API options, mechanism tracing, unresolved decisions, source provenance and this review.
- The acceptance plan defines 91 unique planned test IDs. None is implemented or executed.
- The register contains 18 security invariants, 21 threats, 22 security controls and 14 open questions.
- Local Markdown links and referenced test/invariant/threat/control IDs were checked mechanically.
- The preserved original requirements match the supplied attachment by SHA-256.
- Markdown code fences are balanced.

The validator and machine-readable result are development scratch files under work/ on E:. This is package QA only; it does not validate any Portico security behavior.

## Consistency decisions checked
1. **Authority:** TLS/registry identity is immutable; usernames never authorize. Grants explicitly select devices and resource revisions. HostBindings are independent. Management-kind resources also require active administrator identity/authority.
2. **Activation:** authorize → dial exact tuple → confirm activation against current policy → forward bytes. A concurrent revocation can race the socket attempt; application forwarding remains subject to cancellation and finite leases.
3. **Revocation:** deny new decisions on authoritative commit; connected cancellation target 2 seconds; partition lease at most 15 seconds from request start plus 1-second measured scheduling tolerance. No instantaneous distributed termination claim.
4. **Renewal:** an old admin certificate alone cannot extend authority; issuer bypass routes are a gate. Planned overlap and compromise replacement are separate.
5. **Clock:** no skew grace extends expiry; suspend/restart/rollback cannot preserve stale leases. Calendar schedule, timezone and lifetime cap are distinct.
6. **Recovery:** root/console remains an independent high-trust path. Stale authentic backups restore only in quarantine and cannot automatically resurrect revocations, sessions or invitations.
7. **Secrets:** invitations are stored as verifiers and delivered once after approval. Redisplay is unavailable; lost delivery needs a new approved invitation. Device keys remain local.
8. **Networking:** no L3 mesh, global DNS ownership or Internet exit. Docker/LAN/IPv6 isolation and Mullvad coexistence require independent deployment evidence.
9. **Platform:** Android client remains mandatory MVP, Windows connector may follow, Android connector is optional. Single-VPN and local-loopback limitations remain explicit.
10. **Distribution:** release trust is distinct from identity CA trust. Supported distribution requires authenticated artifacts; safe rollback cannot revert security state.

## Material unresolved risks
Q01/Q02/Q03/Q05/Q06/Q08/Q12 require explicit resolution or evidence before their dependent security claims. Especially:
- The candidate reverse-stream adapter has not been implemented or reviewed.
- Browser/device binding and stable WebAuthn origin are unsolved integration gates.
- Hardware independence/attestation cannot be inferred merely from a credential ID.
- Partition-bound revocation semantics need acceptance and measurement.
- Connector/application compromise is bounded by actual network segmentation.
- Physical recovery cannot promise protection from host root.
- No actual Docker, Mullvad, Android or key-provider compatibility testing has run.

## Scope boundary
All project documents and scratch work created for this task reside in E:\Portico. E: was inspected as a fixed NTFS volume. No Portico application code, repository CI, installer, service, firewall rule, VPN change, DNS change, key material or public deployment was created.

Limited upstream source files were read as research scratch. No upstream code was incorporated into a Portico implementation. No repository was published.

**Phase 0 stops here. Phase 1 requires explicit authorization.**
