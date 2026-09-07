# Contributing

Current scope: Phase 1 repository and quality foundation. Phase 2 domain implementation is not started.

Use [development instructions](docs/development.md) and [testing instructions](docs/testing.md). On this development machine keep source, downloads, caches and test output on E:. The supplied scripts configure only their process, not global machine settings.

Before a change:
- Identify the relevant invariant, trust boundary and open design gate.
- Keep application and developer-tool dependencies separate.
- Use explicit version/checksum pins and review dependency changes.
- Run the applicable checks; security changes require meaningful negative tests and observed outcomes.
- Update the documentation and actual evidence status. Never replace a planned security test with an empty passing test.

Keep changes small and explain what changed, why and how it was verified. Do not modify real networking or publish experimental services. Do not add generic controller/connector placeholders that pretend to authorize access.

Project licensing and repository ownership remain Q13. No license has been selected on the owner's behalf; publication/contribution terms must be resolved before accepting external contributions.

Before configuring a hosted repository, establish private reporting, branch protection/required checks and maintainer review ownership. Local workflow files alone do not enable those server-side controls.
