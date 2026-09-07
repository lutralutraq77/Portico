# ADR-001: Implementation language and supporting technology

Date: 7 September 2026
Status: Accepted for the authorized Phase 1 foundation, using Go 1.27.1. Revisit before data-plane work if platform gates fail.

## Context and options
Portico needs a maintainable memory-safe networking core, established TLS/mTLS, OS key-provider integration, Linux/Windows deployment and a required Android client. The team and throughput requirements are unknown; no benchmark claims are available.

| Criterion | Go | Rust | C#/.NET | C/C++ |
|---|---|---|---|---|
| Memory safety | Managed memory; races/unsafe/cgo still matter | Strong ownership model; unsafe/FFI still matter | Managed memory; unsafe/native interop still matter | Manual lifetime risks increase review burden |
| Networking/TLS | Standard library TLS/X.509 and established gRPC | rustls/Tokio ecosystem; explicit crypto provider/async choices | Mature networking/OS TLS; runtime considerations | Mature libraries available, integration burden higher |
| Windows/Linux | Straightforward core builds; native key adapters required | Strong native targets; Windows adapters still required | Particularly good Windows integration; Linux viable | Broad targets but manual integration |
| Android | Native Kotlin plus narrow binding; not automatic | Kotlin/JNI possible; FFI complexity | Mobile tooling exists; assess runtime/UI fit | JNI supported, significant safety burden |
| Deployment | Often simple binary; cgo/platform drivers may change that | Native binary; cross-build/toolchain complexity | Runtime/self-contained choices need qualification | Native binary plus system libraries |
| Maintenance | Smaller core language; established operational network projects | More compile-time correctness, steeper async/FFI maintenance | Good tooling, larger runtime assumptions | Highest security review cost here |
| Runtime tradeoff | GC, allocation/latency and key-memory copies | Predictable ownership; difficult API/lifetime design | GC/runtime size | Manual control with manual hazards |

These are engineering assessments, not evidence that one language guarantees security.

## Decision
Recommend **Go for controller, policy domain, connector and shared desktop client core**. Use standard TLS/X.509 and reviewed dependencies. Prefer narrow interfaces with cancellation and bounded memory; no bespoke cryptography.

Reasons: good fit for concurrent services, operational simplicity and direct standard-library crypto APIs. OpenZiti and Smallstep offer inspectable Go implementations of adjacent identity/networking concerns; that supports ecosystem suitability without implying their security properties transfer to Portico.

Rust is a credible alternative, especially if measured throughput/latency or a low-level client component makes GC unacceptable. Rust plus rustls needs review of crypto providers, unsafe dependencies and OS-key interoperability. [rustls repository](https://github.com/rustls/rustls). Reject C/C++ as the primary core due to additional memory-safety burden. C# remains a possible Windows shell, but a second full authorization implementation would create parity risk.

## Key-provider and mobile gate
Go's crypto.Signer interface permits external signing integration; it does not itself supply Android Keystore or Windows TPM support. TLS supports authenticated peers and custom verification hooks, which must preserve standard chain/name validation. [crypto.Signer](https://pkg.go.dev/crypto#Signer) · [crypto/tls](https://pkg.go.dev/crypto/tls).

Use Kotlin for Android UI, lifecycle, Keystore and any VPN-specific integration. Evaluate a narrow shared-core binding using established mobile tooling, and compare a native networking adapter against Go binding complexity. [gomobile documentation](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile).

Before adopting this as final for the data plane, prove local non-exported signing, cancellation, suspend expiry, memory limits, packaging and real-device reconnect. No Go toolchain or Android SDK is installed in Phase 0.

## Other technology recommendations
- Dashboard: TypeScript + Angular Material, using Material Design 3 tokens, dialogs, navigation and responsive layouts. A framework is justified for the requested multi-page admin product, not used to implement crypto/network transport.
- Angular Material's official theming guide describes its design-system integration. Google's separate Material Web library is marked maintenance mode; do not select it merely because its name matches the requirement. [Angular theming source](https://raw.githubusercontent.com/angular/components/main/guides/theming.md) · [Material Web status](https://github.com/material-components/material-web).
- Issuer: evaluate self-hosted step-ca behind a restricted registration authority; Q08 gates admin renewal.
- Storage: single-writer SQLite for first self-hosted controller; Q09 chooses driver and migration strategy. HA/PostgreSQL is a later change.
- Protocol: standard TLS 1.3 with reviewed HTTP/2/gRPC carrier candidate; Q01 compares reuse of OpenZiti and direct standard-TLS adapters.
- WebAuthn: maintained server library selected against conformance, authenticator policy and update history; no homemade CBOR/signature parser.
- Backup/update: reviewed age/TUF tooling after dependency/version review.

## Consequences and acceptance
Go's memory safety does not remove authorization bugs, timing races, panic-based denial, GC pauses, secret copies or unsafe/native dependency risk. Keep OS bridges small and independently tested. Avoid two competing policy engines across platforms.

Phase 1 chooses exact supported toolchain/dependency versions and pins them; a current package page is not a future version policy. Use profiling and hostile-load tests before assigning resource/latency budgets. Failure of Q01/Q02/Q03/Q11 reopens this ADR rather than weakening the security model.
