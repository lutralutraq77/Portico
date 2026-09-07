# Open questions and decision gates

Status: active design gates. Q09 is resolved for Phase 2 local storage by ADR-002. [ADR-004](ADR-004-restricted-issuer-admin-recovery.md) records restricted issuer, TLS-bound administrator and recovery components. Q02/Q03 remain open: the owner is undecided on both key models and the private hostname. Q08 now has real issuer/bypass lab tests, but deployment/custody and administrator renewal are not qualified. Recommended assumptions never authorize an insecure fallback.

| ID | Decision / conflict | Recommended direction | Evidence required and owner role | Gate |
|---|---|---|---|---|
| Q01 | Mature data fabric reuse versus Portico reverse-stream adapter; nested TLS/cancellation/quotas | Compare embedded OpenZiti with standard-TLS/gRPC carrier; prefer small reviewed boundary if parity is proven | Network/security engineer: dependency comparison, protocol review and hostile-load/cancellation/mobile tests | Before Phase 5 connector prototype; review design before protocol implementation |
| Q02 | Browser certificate factor, stable private WebAuthn origin, IP-only bootstrap and key-store access | Native companion with server-verifiable device binding; server TLS/WebAuthn components are isolated per ADR-004 | Identity/frontend/platform reviewers: complete browser/native sequence and malicious-origin/local-user tests | Before browser/native administration and Phase 7 dashboard |
| Q03 | Hardware proof, independent recovery key, UV-capable device support and offline attestation metadata | Require supported UV hardware authenticators, not attachment hints or arbitrary synced passkeys | Security/platform reviewer plus owner: actual two-key matrix and attestation trust procedure | Before admin enrollment is production-capable |
| Q04 | Hostname convenience versus rebinding and dynamic IP changes | Exact reviewed IP set; pause on change; literal IP first | Network engineer: canonicalization/CNAME/A+AAAA policy and DNS race tests | Before hostname resource support |
| Q05 | “Immediate” revocation under partition cannot be instantaneous | Commit-deny plus connected 2-second target and at most 15-second request-anchored lease (+1-second qualified scheduler tolerance) | Security/product owner: explicit acceptance of bounded semantics and measured evidence | Before data-plane security claims; do not silently reinterpret requirement |
| Q06 | Physical recovery assurance across console, remote root, VM and OS | No recovery HTTP API; local interactive maintenance plus independent recovery material | Deployment/security reviewer: supported ceremony and recovery drill | Before bootstrap finalization/production |
| Q07 | TCP loopback does not isolate other OS users; Android app compatibility | Explicit single-user device scope or protected IPC/qualified per-user isolation | Platform engineer: malicious-local-user tests and real application flows | Before shared-machine support claims |
| Q08 | step-ca registration-authority/provisioner constraints and admin renewal | Restricted embedded service has pinned mTLS, CSR-bound tokens, exact profiles and durable receipts; no stock router | PKI engineer: lab bypass tests implemented; qualify network isolation, custody/rotation and administrator renewal | Before deployment; administrator renewal remains disabled |
| Q09 | SQLite driver, migrations, encryption-at-rest boundary and backup consistency | One authoritative writer on local storage; no HA yet | Storage/security engineer: dependency review, transactional audit and restore/migration tests | Resolved for Phase 2: ADR-002; encrypted recovery and deployment qualification remain later gates |
| Q10 | Release signing quorum, update verifier, metadata expiry and recovery custody | Independent TUF trust with real maintainers and offline root custody | Maintainers/security engineer: actual custodians, verifier review and rotation drill | Before first distributed authenticated release |
| Q11 | Minimum OS versions, architectures, Go/Kotlin bridge and key-provider behavior | Qualify Windows/Linux x86_64 and Android arm64 first; evaluate ARM Linux | Platform engineer: real-device build/key/suspend/app tests and maintenance capacity | Before platform support promises; Android remains mandatory MVP |
| Q12 | Supported Docker/kernel/firewall profile and host-wide Mullvad installations | Independently segmented Linux deployment; no automatic VPN/firewall conversion | Deployment engineer/owner: isolated dual-stack and real Mullvad qualification | Before production networking |
| Q13 | Project license, name collision and maintainer response commitments; repository owner is lutralutraq77 and private reporting is enabled | Public development repository now exists, but the original governance gate is not fully closed; no invented email or legal grant | Project owner/maintainers: explicit remaining governance/licensing choices and reporting exercise | Resolve remaining items before external contributions or a supported release |
| Q14 | Admin lifetime cap, recurrence policies, audit retention and resource budgets | Conservative defaults in session/protocol docs; configure within reviewed bounds | Product/security/operations reviewers: usability, mobile load and recovery evidence | Before stable configuration contract |

## Resolved direction, progressively implemented
Exact device/resource grants; independent HostBindings; no user-key escrow; no cloud identity dependency; no L3 mesh/default route; no global DNS change; no public dashboard; separate issuer and release trust; local recovery; TCP first; Android client mandatory.

## Explicit limits
- A compromised connector may expose any workload its OS/network can reach. Controller API separation is not network containment by itself.
- A permitted SSH/proxy/application can initiate onward connections. Per-port Portico authorization cannot prove application confinement.
- Root can tamper with local controller data and perform privileged recovery. Dashboard permissions do not protect secrets from root.
- Two simultaneous Android VpnService instances in the same profile are not a supported coexistence promise.
- No numeric revocation target has been measured yet.
- Bootstrap has no approved browser-origin fallback; implementation must resolve Q02.

These limits do not waive invariants. They define the boundary to be designed and tested. When a proposed feature requires changing an invariant, record a new decision and stop that affected work for explicit review.
