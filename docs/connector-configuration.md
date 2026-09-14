# Development connector command

The Linux development binary exposes portico connector run --config /absolute/path/config.json. It connects only to explicit loopback controller/carrier endpoints and opens destinations only after the workload protocol authorizes them. It installs no service. Controller packaging, deployment network profiles, key enrollment tooling and supported releases remain separate work.

## Local files

The configuration is JSON version 1, with a 64 KiB limit, no duplicate/case-alias keys, unknown fields, trailing values or inline secrets. The complete schema is internal/connector.FileConfig. It contains deployment/certificate identifiers, separate device and connector trust roots/issuers, the connector leaf/key file paths, pinned controller/carrier endpoints, exact destinations, protected networks and bounded limits. No clock-health override is accepted. Destinations use resource_id, revision, address, port and protocol fields; protocol is tcp.

All referenced files require canonical absolute paths. Linux opens each directory relative to an already checked directory descriptor and refuses symlinks. Root or the effective service UID must own every ancestor and file; group/other write permission is rejected, including shared temporary directories with a sticky bit. The final file must be regular, singly linked, nonempty and within its size limit, and its metadata must remain stable across the read. File descriptors are close-on-exec. [Linux descriptor-relative open semantics](https://man7.org/linux/man-pages/man2/open.2.html), [file metadata](https://man7.org/linux/man-pages/man2/stat.2.html).

The key file additionally excludes group/other access and execution: 0600 or 0400 under a protected directory is suitable. The loader expects exactly one PKCS#8 PRIVATE KEY PEM block and an already-issued connector leaf that matches it. Trust files contain exactly one certificate per file; configured issuing intermediates supply the TLS chains. The key remains local to the connector process. This is a protected-file software-key path, not a hardware-backed key-store claim. Raw parsing buffers are cleared where possible; Go heap erasure is not guaranteed. The service UID and host administrator are trusted.

Windows and other platforms without native file-protection support fail closed. The loader does not chmod, chown, follow alternative paths, invoke a password prompt or repair configuration. Errors do not echo file paths or key material. Paths and limits must be supplied explicitly; no production identities or keys are supplied by the repository.

## Runtime

control and carrier each contain url, root_certificate_file and spki_sha256. Both use pinned HTTPS/mTLS and the same normalized connector identity as the inner TLS server. This development command restricts endpoints to localhost or a literal loopback IP. The independently approved destination tuples and protected_networks still undergo complete workload validation before a carrier binding can start.

workers is 1–64 and bounds pending/active streams together; max_device_sessions must fit that bound. operation_timeout_ms is 1–5000 and idle_timeout_seconds is 1–900. Rebinding uses 500 ms to five-second exponential backoff. The [connector runtime](connector-runtime.md) owns closure and joins workers; SIGINT/SIGTERM cancel its context and wait for shutdown before process exit. The controller client remains alive until that join completes.

The command always selects the [native Linux clock-health provider](connector-clock.md). Unusable native health rejects startup before a binding; later failure terminates the runtime. It never configures the host time service or sets the clock. Restart starts a new process/runtime and restores no leases.

## Test boundary

Native Linux tests reject unsafe permissions, foreign ownership, symlinks, hardlinks, FIFOs, oversized files and writable directory traversal. The isolated process test first requires the real command to reject the guest's unsynchronized kernel and an overly readable key file. Its positive path then supplies synthetic NTP synchronization metadata to the disposable NIC-less kernel, runs the real command with native health, forwards an exact-resource echo and exercises SIGTERM, SIGKILL and fresh-session restart. It restores the original unsynchronized metadata after the processes join. That fixture changes neither UTC nor the host clock and proves no upstream time-source accuracy. The read-only provider tests themselves never alter kernel state. [Recorded verification](phase-5-connector-command-report.md).

Successful component/process tests do not qualify an installed service, real NTP configuration, hardware key custody, physical suspend, independent egress isolation or the full acceptance matrix.
