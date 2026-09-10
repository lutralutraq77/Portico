# Phase 6 ordinary enrollment transport evidence

The ordinary device and connector enrollment transport passed native Windows and Linux quality checks and the complete isolated Linux runtime suite on source `a1e284ca09b71c7acedb73fb16e4fd5bf222ee6a`. It composes the controller's durable invitation/attempt records, the restricted Smallstep issuer, and actual fresh TLS activation. These are development components with loopback-only endpoints. Encrypted local key/attempt storage, an enrollment command and installed services were not part of this verified source.

The [transport contract](enrollment.md), [machine-readable evidence](phase-6-enrollment-evidence.json) and [delivery ledger](delivery-status.md) describe the boundary and remaining work. No canonical acceptance case is promoted: seven of 91 remain implemented and 84 planned. This evidence does not complete Phase 6 or the fifteen-phase objective.

## Implemented boundary

Redemption authenticates the pinned server before delivering the invitation secret. The server checks the configured issuer/profile before reserving an invitation and derives identity and lifetime from controller records. An empty proof-only CSR binds the local key to one durable attempt. The signing provider is invoked at most once; repeat retrieval returns the registered public result. A lost issuer response remains ambiguous and requires trusted receipt reconciliation or revocation and a new approved invitation. No remote reset or reconciliation capability was added.

Activation is a separate server configuration with no signing provider. It authenticates the actual TLS peer against the pending/active certificate registry and the invitation binding. A certificate in an HTTP body, header or synthetic TLS state cannot activate an identity. The client checks the returned principal, public key, issuer/profile, exact approved expiry, invitation and attempt before starting fresh TLS 1.3 activation. Administrator enrollment is excluded.

Both ends enforce strict versioned JSON, fixed routes, 16 KiB bodies, bounded admission and deadlines. The server permits at most 32 connections and eight active requests with no application queue. Redirects, environment proxies, compression, connection reuse and TLS resumption are disabled. Close cancels in-flight work; a cancelled ambiguous signing attempt is not released for another signature. Request-body reading and erasure use the same lock because HTTP transport cleanup can continue after an error returns. This clears owned mutable buffers without claiming forensic erasure of all Go allocations.

Actual HTTPS tests cover server authentication before secret delivery, wrong issuer/profile, changed keys/attempts, claim-bearing CSRs, repeated retrieval, overload, cancellation, strict routes/headers, ambiguous signing/reconciliation, and revoked/expired identities. The composed real Smallstep test exercises both ordinary profiles and pending/active/revoked TLS admission. Public certificate possession alone is insufficient.

## Source-specific verification

All five hosted jobs completed successfully on 10 September 2026:

- [Complete NIC-less Linux runtime](https://github.com/lutralutraq77/Portico/actions/runs/34474851954), job `102863061447`.
- [Full Windows and Ubuntu quality matrix](https://github.com/lutralutraq77/Portico/actions/runs/34474852002), jobs `102863061384` and `102863061690`.
- [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34474851880), job `102863060668`.
- [Dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34474851844), job `102863060674`.

The PR jobs checked merge commit `12f6ee4ec78aa2b202c34e1972d7e3d1df759dfc`. Its Git tree and source head's tree are both `16d2915035a588b659cbb029597bb6e181e75fcf`; this was verified locally. Native quality runs executed both Go modules' unit/race tests, seven fuzz targets, static/dependency/secret/workflow/documentation checks, scanner positive controls, reproducible builds and SBOM verification. The enrollment and real issuer tests appear in the archived logs. The gRPC advisory detected during earlier dependency review was fixed in both modules with upstream gRPC 1.83.2 and x/net 0.58.0; no advisory was suppressed.

The complete guest ran 172 passing top-level tests, 792 passing test subcases and 36 seeds across seven fuzz targets. One issuer subprocess-helper entry intentionally skipped; there were zero failures and the final marker was `PORTICO_LINUX_ALL_PASS`. The synchronized request-body regression, real issuer ordinary workflow and both connector revocation/restart/replay subcases passed. This guest run is not race instrumented; native race checks are separate evidence.

Ubuntu 24.04.5 hosted pinned QEMU 11.1.1 TCG with two virtual CPUs, 1536 MiB RAM, no NIC and no host filesystem shares. The QEMU source archive's detached signature was verified against the upstream release key before pinning its SHA-256. The harness builds that exact source without additional downloads, verifies the pinned kernel, and records the actual emulator and initramfs hashes. See [Linux runtime provenance](linux-runtime.md).

Guest artifact `10151415167` was downloaded and its ZIP digest verified against GitHub metadata before extracting only the named reports. ZIP SHA-256: `50892b07baaa44a4a40ee158759b7ac4ba5c861db60682ab7c721b47721674ea`. Guest log SHA-256: `3e82af29c0534ccfbe6b39effa1a24d44269c78e2547bc0a6218aef686bfb8a6`. Job logs, environment data and the ZIP are archived under `work/reports/phase-6-enrollment-resumed`; the evidence JSON records their hashes. Native artifact digests were read from GitHub metadata; those ZIPs were not downloaded and locally digest-verified.

## Retained failures and remaining scope

The earlier full local Linux run on `ffed109c8e06ca8aec9ff04b6c8010bd447011ba` failed initial connector setup in both revocation subcases before revocation occurred. Its log remains archived with SHA-256 `028dbbef7695693d7a98be1a03e47bf3b23c5a2a0e9888b6e7ff60730c882644`. Focused diagnostic archives retain additional setup timeouts and one native clock acquisition of 131.7 ms against the unchanged 100 ms limit. The successful independent hosted run does not establish all earlier failures' causes. No production or fixture deadline, clock predicate or security check was relaxed to obtain a pass.

The caller must still durably preserve its original local key and attempt before redeeming. Later durable-file and encrypted-state changes need their own verification and are not covered by this source's results. Platform keystore custody, same-user IPC isolation, desktop/browser workflows, Arch services/packages, Windows/Android clients, physical administrator keys and recovery, independent network isolation, qualified time sources, signed updates and the full acceptance matrix remain required. No merge, deployment, host trust/network/clock change or physical qualification is claimed. The preserved master brief SHA-256 remains `653b502484f8932c9b2a4faa40b02248c0215407996882e74fbfb3adeef6b37f`.
