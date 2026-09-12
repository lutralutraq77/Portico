# Phase 5 connector command progress

Implementation source 7ddb5c8143acd3cb653dc5ef023c4e61d0e754b0 passed full local Windows, full isolated Linux and hosted Windows/Ubuntu checks. The development CLI now reports 0.5.0-dev and exposes a Linux connector command with protected local configuration, native clock health and joined shutdown. Phase 5 qualification and the complete fifteen-phase objective remain in progress. [Command contract](connector-configuration.md), [runtime contract](connector-runtime.md), [machine-readable evidence](phase-5-connector-command-evidence.json), [draft PR 4](https://github.com/lutralutraq77/Portico/pull/4).

## Implementation and process evidence

The command derives one validated connector identity for control, carrier and inner TLS, restricts development control/carrier endpoints to loopback and accepts only explicit destination configuration. Its bounded pool retries new bindings after idle expiry/failure, never replays application data, and joins workers before reusing a stream slot. Clock failure also stops idle pools. No stored lease resumes after restart.

Linux configuration reads validate directory/file ownership, permissions and type using descriptor-relative opens without symlink following. Private keys exclude group/other access. Duplicate or unknown JSON fields, inline clock-health overrides, mismatched keys and malformed file/configuration inputs fail closed. Windows has no configuration-file or clock-health fallback. The command installs no service and changes no host networking or time settings.

The Linux process test runs the real binary, rejects unsynchronized startup and an overly readable key, forwards an exact-resource echo, handles SIGTERM and SIGKILL, and restarts with distinct session IDs. Terminated client streams cannot forward again. Its positive path explicitly supplies synthetic synchronization metadata inside the disposable kernel and restores the initial unsynchronized state after the processes join. It changes neither UTC nor the host clock and does not establish upstream time accuracy. The native provider's separate read-only test rejects the actual initial TIME_ERROR/STA_UNSYNC kernel state.

## Verification at 7ddb5c8

The complete NIC-less Linux run passed 139 top-level tests, 480 subtests and 36 seeds across seven fuzz targets, with one intentional issuer subprocess-helper skip. The real command/process test passed; the CLI smoke output reported 0.5.0-dev. The runtime was Linux 6.18.35-0-virt under QEMU 11.1.0 TCG, without a NIC or host filesystem shares. The final marker was PORTICO_LINUX_ALL_PASS. This run is not race instrumented.

The full Windows check ran without skip flags and passed both Go modules' unit/race tests, all seven bounded fuzz targets, vet/static analysis, application/issuer/tool vulnerability checks, scanner positive controls, workflow/documentation/secret checks, development builds, reproducibility and SBOM/provenance checks. Workload-open fuzzing executed 92,693 inputs. Native POSIX protection and guest-only destination/process tests are covered by the separate Linux evidence, not by Windows skips. The imported-package scans found no affected packages; one advisory in required modules outside those imported packages remains visible in the scanner output.

[Hosted quality](https://github.com/lutralutraq77/Portico/actions/runs/34176662453), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34176662439) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34176662446) completed successfully for this source. Both quality matrix jobs ran the full check script and uploaded evidence. Later documentation commits retain this exact implementation checkpoint; their own hosted status must be checked separately.

| Archived artifact | SHA-256 |
|---|---|
| Full Windows check | E8CA7577DDE258E49335BA266D81559C74224327C9DB2F2F72C0235CE26D0F37 |
| Full Linux serial log | CC7BCBF65A12D8BAE0A76C0F11D3C6F0422062C7D9D5AAA31C116DFD97D0AE7E |
| Focused Linux serial log | F54D60C3FA28239788E2D8E0E09B23A3D2825E0D9B8F8FD618B5CD5BF2D9CCA9 |
| Windows development application | D694B65E972EA9D9690AFF98C601D723EAFA5A2BEC6F3A37C428D59E0C34C029 |
| Linux development application | 23E376E929FC99EA78F50870BC7EE25D3A76AC425C72AD758E66C7748F55AF70 |

The local archive is work/reports/phase-5-config-7ddb5c8, with a separate artifact hash manifest. The focused Linux run passed 37 top-level tests, 103 subtests and two fuzz seeds, no skips; its marker is PORTICO_LINUX_WORKLOAD_PASS, not a complete-suite claim. In the full run, revocation-to-destination-closure-plus-receipt was 166.534298 ms; withheld-renewal request start to destination closure was 1,942.25097 ms. These fixture measurements do not accept Q05 or qualify hostile scheduling/physical suspend.

## Retained failures and preceding checkpoint

Source 40145a0's initial two-stream fixture opened streams sequentially, allowing the second pending binding to expire. Source 3fcad22 opens them concurrently and passed focused Linux, full Windows and all hosted checks. The initial log hash is 2137797BB6206AA6709D76CEE66B5621D720E5807D387991DE9D3D6DCBAC425A; the source-3fcad22 archive is work/reports/phase-5-connector-3fcad22.

Source ef52a9a's first full Linux run rejected the supposedly protected absolute file paths and command configuration. The disposable initramfs root actually had mode 01777. The harness now explicitly sets its guest root to 0755; production loader checks were not weakened. The original failed log is retained under work/reports/phase-5-config-ef52a9a with SHA-256 489606A155F7949F415D2556E99D3973CF8873A9687C590EC694DEE70127431A. The corrected focused and full runs passed.

## Remaining gates

Installed connector/controller/client packaging, qualified host time services, physical suspend, the complete hostile-load/socket/network scenarios and independent egress isolation remain open. Protected software key files do not qualify physical key custody or Windows CNG/ACL behavior. Hardware-key models and the private administrator hostname remain undecided. At this command checkpoint the canonical manifest recorded AUDIT-01 implemented and 90 planned; the later [isolation report](phase-5-isolation-report.md) adds CONN-01 and CONN-03. All development files, builds, caches and evidence remain on E:.
