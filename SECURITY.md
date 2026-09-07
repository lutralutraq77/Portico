# Security policy

Portico is a development foundation, not a supported access service. No production release exists. The current executable only reports development version/help. Phase 2 domain operations are trusted internal storage methods and are not an authenticated access service.

The [security invariants](SECURITY_INVARIANTS.md), [threat model](THREAT_MODEL.md) and [acceptance plan](ACCEPTANCE_TEST_PLAN.md) are mandatory review inputs.

## Reporting
No public repository or private reporting channel has been established. Report concerns directly to the project owner through the private channel already in use. Do not post secrets or exploit details in a public issue. Before public publication, the owner must establish and test private vulnerability reporting and maintainer response commitments (Q13).

No invented email address or unsupported response SLA is promised here.

## Development controls
Go/runtime dependencies, tools and CI actions are pinned. Source checks, dependency vulnerability scanning, secret scanning, static analysis and CodeQL configuration are present. Tool updates require review; a green scanner does not prove security.

No production secrets in PR jobs. No pull_request_target execution of PR code. Read-only CI permissions are default; the CodeQL job has only the extra permissions required for analysis upload. Release credentials are absent.

Security-critical changes need the related threat/control/test updates. Unknown authorization state must fail closed. Reproduction must use isolated fixtures, not the developer's router, firewall, Mullvad, DNS or production server.

## Release gate
Production requires actual runtime acceptance evidence, platform/network qualification, tested recovery/update rollback and independent review. Of 91 runtime acceptance cases, AUDIT-01 has executable Windows/Linux process-crash evidence; the remaining 90 cases are planned. Foundation test results must never be represented as network isolation, certificate authentication or revocation proof.
