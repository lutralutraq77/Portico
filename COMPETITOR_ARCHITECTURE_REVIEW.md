# Comparative architecture review

Research date: 7 September 2026. Primary documentation plus limited source inspection; no full code audit, performance benchmark or security certification of any project.

Twingate is a product/documentation reference, not evidence of an open-source implementation. OpenZiti, NetBird and Smallstep supply inspectable open-source implementations. Teleport's cited locking documentation labels the feature as Enterprise; use its published design as inspiration without assuming that feature's licensing/availability in a reusable edition.

## Patterns and adaptations
| Proven/documented pattern | Source | Portico adaptation | Security reason | Deliberate deviation | Required tests |
|---|---|---|---|---|---|
| Resource-centric access and connector placement | [Twingate architecture](https://www.twingate.com/docs/how-twingate-works/) | Small resource form and private connector-side socket | Minimize network scope | Fully self-hosted identity, explicit single port, no cloud IdP requirement | AUTHZ-01–07 |
| Client/connector connection authorization | [Twingate connection flow](https://www.twingate.com/docs/detailed-client-connection-flow) | Authorize each resource stream and bind device/connector identity | Prevent arbitrary reachability | Online stateful checks/finite leases; no copied token format | SESSION-02–05 |
| Independent Dial and Bind | [OpenZiti policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/creating-service-policies/) | Separate device Grants and connector HostBindings | Hosting permission cannot imply administration or arbitrary dial | Exact device/resource revisions; no implicit attribute/group expansion | CONN-01–04 |
| Routing-peer policy separates forwarded resource and peer-host traffic | [NetBird routing peers](https://docs.netbird.io/manage/networks/how-routing-peers-work) | Distinguish connector host from hosted resource | Avoid incidental peer/host access | No generic IP routing, exit node or legacy broad route | AUTHZ-02–07, NET-07 |
| Per-session MFA protects against stolen on-disk certificates | [Teleport MFA](https://goteleport.com/docs/zero-trust-access/authentication/per-session-mfa/) | Fresh hardware approval per sensitive admin operation/renewal | Stop certificate-only indefinite authority | Exact operation binding, no hosted identity dependence | ADMIN-01–06 |
| Dynamic locks and strict behavior when lock state is stale | [Teleport locking](https://goteleport.com/docs/identity-governance/locking/) | Cancellation push plus finite leases and deny on unknown state | Bound stale authority under partition | Fail-closed baseline and explicit timing targets | SESSION-02–06 |
| Offline root / online intermediate | [Smallstep CA guidance](https://smallstep.com/docs/step-ca/certificate-authority-server-production/) | Restricted issuer behind registration authority | Reduce long-term key exposure | Live registry/policy remain authoritative; no generic admin renewal | PKI-01–06 |
| Server-side deny by default and per-request checks | [OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) | Same API/UI handlers and per-stream decisions | Malicious clients cannot bypass UI controls | Device/resource domain predicate is Portico-specific | AUTHZ-08, ADMIN-07–08 |
| Signed role-separated update metadata | [TUF specification](https://theupdateframework.github.io/specification/latest/) | Independent release trust and protected version floor | Resist malicious/stale distribution | Self-hosted runtime stays usable offline; update expiry remains strict | UPDATE-01–06 |
| Standard mutual TLS rather than custom encryption | [TLS 1.3](https://www.rfc-editor.org/info/rfc9846/) | Endpoint TLS through an untrusted relay | Protect authentication/data independently of relay | Carrier adapter remains a Portico review burden | PROTO-01–05 |

## Source inspection performed
OpenZiti revision **b271a9e48d32dcba596a33f5301196c8bb6138a1**:
- [service_policy_model.go](https://github.com/openziti/ziti/blob/b271a9e48d32dcba596a33f5301196c8bb6138a1/controller/model/service_policy_model.go): examined policy type validation and Dial/Bind mapping.
- [session_manager.go](https://github.com/openziti/ziti/blob/b271a9e48d32dcba596a33f5301196c8bb6138a1/controller/model/session_manager.go): examined identity-scoped service lookup and permission checks on session creation.

Inference for Portico: explicit service permission type should be checked at session creation, not only when showing a catalog. This is limited inspection, not proof of every OpenZiti route or configuration.

Smallstep certificates revision **bb481fbf670c24721d5bdb1489ad0d1052c203b5**:
- [api/renew.go](https://github.com/smallstep/certificates/blob/bb481fbf670c24721d5bdb1489ad0d1052c203b5/api/renew.go): examined peer-certificate extraction and bearer renewal-token path.

Inference for Portico: hiding a dashboard renewal button cannot secure an issuer whose other renewal routes remain available. Administrative renewal must be constrained at the registration-authority/issuer boundary. No claim is made that Smallstep intends to implement Portico's MFA semantics.

Pinned links record the inspected snapshot. Revalidate upstream fixes and licensing before reuse; do not vendor these files based on this review.

## Reuse versus custom work
Strong reuse candidates: TLS/X.509, WebAuthn library, CA service, cryptographic backup format, update metadata verifier and generated RPC parsing. Do not recreate these primitives.

OpenZiti as an embedded data fabric remains a serious Q01 option: compare integration against the proposed standard-TLS carrier before committing to custom network glue. Adoption must preserve Portico's local identity, admin renewal, revocation and no-broad-network semantics. Two controllers with divergent authority are an unacceptable hidden outcome.

Portico-specific work needing extra review: policy predicate, exact resource revisions, browser/device binding, operation-bound step-up state, invitation transaction, lease/cancellation timing, physical recovery, backup anti-rollback, private ingress dispatch and platform key bridges.

## Important non-transfers
Mature protocol use does not prove the composed product secure. A CA certificate does not establish an application role. A short certificate lifetime does not close a live socket. An HTTP/2 relay is not automatically a safe tunnel. A private Docker bridge is not per-resource isolation. An Android build does not prove simultaneous-VPN compatibility.

Research breadth and limits are recorded in [sources](RESEARCH_SOURCES.md). Unresolved choices and required evidence are in [open questions](OPEN_QUESTIONS.md).
