# PORTICO

Self-hosted, resource-oriented private access: identity → policy → resource → connector → destination.

**Current state: Phase 5 development connector is under qualification; full delivery remains in progress.** Exact policy, real issuer, enrollment and recovery components support authenticated workload forwarding with request-start leases and joined-worker closure receipts. The [development Linux command](docs/connector-configuration.md) adds protected configuration files, native clock health and signal-driven shutdown. Its controller/carrier endpoints and the development issuer listener remain restricted to loopback. [Command evidence](docs/phase-5-connector-command-report.md) records the initial verification; [connector isolation evidence](docs/phase-5-isolation-report.md) adds complete CONN-01 and CONN-03 scenarios. Physical security keys, the private sign-in origin, installed connector/client applications and production recovery remain unqualified. The [delivery ledger](docs/delivery-status.md) tracks all fifteen phases.

The project and all generated development storage on this machine are in **E:\Portico**.

## Build and verify
From PowerShell 7 in the repository:

~~~powershell
./scripts/bootstrap.ps1
./scripts/check.ps1
./build/portico-windows-amd64.exe version --json
~~~

Go 1.27.1, scanner modules/checksums, compiler archives and CI action commits are pinned.
Setup changes only the current process environment. It does not modify the machine's routes, DNS, firewall, Mullvad or global tool configuration.

See [development](docs/development.md), [testing](docs/testing.md) and [Phase 2 evidence](docs/phase-2-report.md). Hosted Windows/Ubuntu quality, CodeQL and dependency review passed; see [hosted CI evidence](docs/hosted-ci.md).

## Design package
- [Project brief](PROJECT_BRIEF.md), [architecture](ARCHITECTURE.md), [resource model](RESOURCE_MODEL.md)
- [Threat model](THREAT_MODEL.md), [invariants](SECURITY_INVARIANTS.md), [trust boundaries](TRUST_BOUNDARIES.md), [control matrix](SECURITY_CONTROL_MATRIX.md)
- [PKI](PKI_DESIGN.md), [sessions/revocation](SESSION_AND_REVOCATION_DESIGN.md), [bootstrap/recovery](BOOTSTRAP_AND_RECOVERY.md)
- [Platforms](PLATFORM_SUPPORT.md), [network/Mullvad](NETWORK_AND_MULLVAD_DESIGN.md), [DNS](DNS_DESIGN.md)
- [Updates](UPDATE_SECURITY.md), [protocol/API](PROTOCOL_DESIGN.md), [language ADR](ADR-001-implementation-language.md)
- [Comparative review](COMPETITOR_ARCHITECTURE_REVIEW.md), [sources](RESEARCH_SOURCES.md), [open questions](OPEN_QUESTIONS.md), [roadmap](ROADMAP.md)
- [91 specified runtime acceptance cases](ACCEPTANCE_TEST_PLAN.md), [manifest](tests/acceptance/manifest.json), [historical Phase 0 review](PHASE_0_REVIEW.md)

## Scope and next work
The [policy API](docs/policy-api.md) and [ADR-005](ADR-005-resource-policy-boundary.md) describe Phase 4. The [Phase 3 integration report](docs/phase-3-integration-report.md) preserves its measured evidence and open hardware/browser/recovery gates. [ADR-004](ADR-004-restricted-issuer-admin-recovery.md) and the [issuer guide](docs/issuer.md) describe those boundaries. Component tests do not demonstrate resource isolation, physical recovery or Mullvad compatibility. AUDIT-01 has Windows/Linux process-crash evidence; the other 90 cases remain planned.

Go is selected for the initial core foundation. Android integration, browser/device authentication, hardware-key policy and the mature transport adapter remain explicit design gates. See the [domain implementation](docs/controller-domain.md) and [storage decision](ADR-002-controller-storage.md).

Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [dependency policy](docs/dependency-policy.md) before changing security-relevant behavior. The development repository is public at lutralutraq77/Portico, with private vulnerability reporting enabled. Licensing and supported release governance remain unresolved.
