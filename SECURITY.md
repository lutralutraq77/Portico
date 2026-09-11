# Security policy

Portico is a development foundation, not a supported access service. No production release exists. The current executable includes development Linux enrollment, client, connector and local-agent commands. The [delivery ledger](docs/delivery-status.md) records their tested boundaries and remaining gates; component availability does not establish a supported deployment.

The [security invariants](SECURITY_INVARIANTS.md), [threat model](THREAT_MODEL.md) and [acceptance plan](ACCEPTANCE_TEST_PLAN.md) are mandatory review inputs.

## Reporting
The development repository is public, and GitHub private vulnerability reporting is enabled. Use the private reporting flow from the [repository Security page](https://github.com/lutralutraq77/Portico/security). Do not post secrets or exploit details in a public issue. Maintainer response commitments and an end-to-end reporting exercise remain governance work under Q13; enabling the setting alone does not establish a response SLA.

No invented email address or unsupported response SLA is promised here.

## Development controls
Go/runtime dependencies, tools and CI actions are pinned. Source checks, dependency vulnerability scanning, secret scanning, static analysis and CodeQL configuration are present. Tool updates require review; a green scanner does not prove security.

No production secrets in PR jobs. No pull_request_target execution of PR code. Read-only CI permissions are default; the CodeQL job has only the extra permissions required for analysis upload. Release credentials are absent.

Security-critical changes need the related threat/control/test updates. Unknown authorization state must fail closed. Reproduction must use isolated fixtures, not the developer's router, firewall, Mullvad, DNS or production server.

## Release gate
Production requires actual runtime acceptance evidence, platform/network qualification, tested recovery/update rollback and independent review. Of 91 runtime acceptance cases, seven have executable scenario evidence and 84 remain planned; the [canonical acceptance plan](ACCEPTANCE_TEST_PLAN.md) identifies them. Foundation test results must never be represented as network isolation, certificate authentication or revocation proof.
