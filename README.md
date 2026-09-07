# PORTICO

Self-hosted, resource-oriented private access: identity → policy → resource → connector → destination.

**Current state: Phase 3 issuer, administrator and recovery components, in progress.** Strict PKI, durable enrollment/renewal, a separate restricted step-ca service, TLS-bound WebAuthn approvals and encrypted quarantined recovery are implemented. The main CLI still exposes only help/version; the development issuer command permits loopback only. Physical security keys, the private sign-in origin and production recovery remain unqualified.

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
The [Phase 3 integration report](docs/phase-3-integration-report.md) records current implementation, tests and open hardware/browser/recovery gates. [ADR-004](ADR-004-restricted-issuer-admin-recovery.md) and the [issuer guide](docs/issuer.md) describe the new boundaries. The [earlier foundation report](docs/phase-3-report.md) preserves its original evidence. Component tests do not demonstrate resource isolation, physical recovery or Mullvad compatibility. AUDIT-01 has Windows/Linux process-crash evidence; the other 90 cases remain planned.

Go is selected for the initial core foundation. Android integration, browser/device authentication, hardware-key policy and the mature transport adapter remain explicit design gates. See the [domain implementation](docs/controller-domain.md) and [storage decision](ADR-002-controller-storage.md).

Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [dependency policy](docs/dependency-policy.md) before changing security-relevant behavior. The development repository is public at lutralutraq77/Portico, with private vulnerability reporting enabled. Licensing and supported release governance remain unresolved.
