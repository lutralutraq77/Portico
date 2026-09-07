# Dependency and supply-chain policy

Application module: modernc.org/sqlite v1.58.0, modernc.org/libc v1.75.6, github.com/google/uuid v1.6.0, age v1.3.2, go-webauthn v0.18.0 and go-jose v4.1.5. The separate issuer module pins Smallstep certificates v0.30.2. See [ADR-002](../ADR-002-controller-storage.md) and [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) for review, licenses and boundaries. The issuer's inherited gRPC/OpenTelemetry/pgx/JOSE v3/x-crypto packages have explicit security updates in issuer/go.mod. UI and forwarding transport remain unselected.

Development tools are isolated in tools/go.mod and tools/go.sum with exact versions and Go checksum verification. tools/toolchain.lock.json pins local SDK/compiler downloads and their SHA-256 values from official Go/GitHub release metadata. Those hashes provide download integrity relative to those trusted sources, not an independent cryptographic audit.

CI actions are pinned to full commit hashes resolved from official repositories. Dependabot proposes updates; maintainers review them and rerun checks. No unpinned latest downloads or curl-to-shell bootstrap.

For any new dependency document purpose, maintainer/release health, license compatibility, vulnerability state, transitive cost and how removal/upgrading works. Review runtime and development dependencies separately; developer tools also process untrusted source and must be maintained.

Use govulncheck for reachable application vulnerabilities, static analysis for code defects, Gitleaks for secrets and CodeQL in hosted CI. None is a proof of absence of security defects. Generate an SBOM alongside future binaries and retain dependency provenance.

Do not commit signing keys, enrollment secrets, production configuration, or reusable credentials. No signing/upload/deployment secrets in PR workflows. Hosted development CI is authorized; no supported release is implied.
