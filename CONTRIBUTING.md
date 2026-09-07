# Contributing

Current scope: Phase 3 PKI/enrollment component work, following the verified and merged Phase 2 controller foundation. Changes must retain the full Windows/Ubuntu quality, CodeQL and dependency-review checks; see docs/phase-3-report.md for current evidence and open gates.

Use [development instructions](docs/development.md) and [testing instructions](docs/testing.md). On this development machine keep source, downloads, caches and test output on E:. The supplied scripts configure only their process, not global machine settings.

Before a change:
- Identify the relevant invariant, trust boundary and open design gate.
- Keep application and developer-tool dependencies separate.
- Use explicit version/checksum pins and review dependency changes.
- Run the applicable checks; security changes require meaningful negative tests and observed outcomes.
- Update the documentation and actual evidence status. Never replace a planned security test with an empty passing test.

Keep changes small and explain what changed, why and how it was verified. Do not modify real networking or publish experimental services. Do not add generic controller/connector placeholders that pretend to authorize access.

The development repository is public at lutralutraq77/Portico. Private vulnerability reporting is enabled. Project licensing, maintainer response commitments and external contribution terms remain Q13. No license has been selected on the owner's behalf.

Before accepting external contributions or approving production use, establish required checks/branch protection, maintainer review ownership and reporting response commitments. The current PR is development work; local workflow files alone do not establish those server-side controls.
