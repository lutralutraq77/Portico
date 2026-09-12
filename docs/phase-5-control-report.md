# Phase 5 control transport progress

The connector control path is implemented and verified locally on revision 518f13992b75692b92de21e5c10a2f348eab37f9. Revision 854a9e134b39643ab7f5160e5d9cdc67dfebe2ee adds a native elapsed-clock component. These are inputs to the workload runtime; Phase 5 and the full fifteen-phase objective remain incomplete. [Draft PR 4](https://github.com/lutralutraq77/Portico/pull/4) retains the full scope. The [API contract](policy-api.md), [clock contract](connector-clock.md) and [machine-readable evidence](phase-5-control-evidence.json) describe the boundaries.

## Implemented behavior

- Devices can check the actual inner connector certificate against current resource authority. Connectors receive complete bounded hosting snapshots, then use a strict pinned HTTPS client for authorization, activation, renewal and closure. The client has no controller database, issuer or administrator dependencies.
- Durable cancellations repeat until acknowledged by their original live connector certificate. Empty polls subscribe before reading, wake after committed changes and repeat the authoritative check. Per-certificate and global wait limits apply across connections. Read-only transactions and rolled-back mutations do not signal a change.
- Polls can select the process's tracked session IDs. A regression test puts 65 old unacknowledged sessions before a newer live session, then confirms prompt delivery for that selected session without falsely acknowledging the older ones. Lost responses repeat; replacement certificates and out-of-selection responses cannot cross the ownership boundary.
- Schema 5 stores immutable, idempotent closure reports and migrates supported prior controller schemas atomically. Audit/storage failures roll back. Reports and pending targets survive restart. A report is authenticated testimony from a connector; its eventual owning runtime must actually close and join the forwarding work before reporting.
- Disabling an authority cancels only sessions that depend on it. Tests revoke one grant while another resource remains usable through the same TLS connection.
- Native clock reads use Linux CLOCK_BOOTTIME and the Windows QueryInterruptTimePrecise API-set contract. Native conversion overflow or an unavailable API fails closed. This does not yet enforce a lease or qualify physical suspend, hibernation or UTC clock health.

## Verification and exact scope

On 518f139, the full Windows scripts/check.ps1 run passed without skip flags: both Go modules' unit/race tests, six bounded fuzz targets, vet/static analysis, application and imported issuer/tool dependency checks, scanner positive controls, secret/workflow/documentation checks, development builds, byte-identical native rebuilds and SBOM/provenance checks. The carrier fuzzer executed 20,361 inputs in that run. An additional imported-package scan of controller, control client and clock code on 854a9e1 found no affected imported packages; the unrelated module advisory remains visible.

The isolated Linux run on 518f139 passed 101 top-level tests, 377 subtests and 34 seeds across six fuzz targets, with one intentional subprocess-helper skip. It used kernel 6.18.35-0-virt and QEMU 11.1.0 TCG, guest loopback, no NIC and no host filesystem shares. It was a real Linux runtime run without race instrumentation; Windows race tests ran separately.

The native clock package on 854a9e1 separately passed Windows unit/race, vet and static analysis. Its subsequent complete Linux VM run passed 103 top-level tests, 377 subtests and 34 fuzz seeds, with one intentional helper skip; this includes both native clock tests. Cross-compilation of the unsupported-platform error path is not platform qualification. The first Windows test exposed an unavailable direct kernel32 export; the implementation now resolves the documented system API-set contract and passes on this host.

Hosted CodeQL and dependency review passed on 518f139. Hosted Windows/Ubuntu quality was still running at that checkpoint. The later control/clock documentation head ca0009ddfa5afc3e43e07285241301250f6c67f7 passed [Windows/Ubuntu quality](https://github.com/lutralutraq77/Portico/actions/runs/34164552302), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34164552279) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34164552280). New workload source requires its own results. Earlier carrier qualification on f1f190b remains recorded in the [carrier report](phase-5-report.md).

Local evidence for 518f139 is archived under work/reports/phase-5-control-518f139 with file hashes. The earlier 86d8205 control checkpoint also passed the full local suite and Linux runtime; its independent archive is retained. The development main executable remains help/version only, so unchanged development binary hashes do not imply these library APIs are packaged as a usable connector.

## Next required work

At this control checkpoint the workload path remained to be composed. Subsequent implementation is described in the [workload contract](workload-runtime.md): actual inner TLS, locally approved tuples, authorization before dialing, activation before bytes, owned handles/workers and request-start deadlines. The full socket-count, delayed-response, partition, replay, restart, suspend and hostile-load acceptance scenarios still require qualification.

The canonical acceptance manifest remains 91 cases: AUDIT-01 implemented and 90 full scenarios planned. Q05's timing acceptance remains unanswered. Hardware models and the private administrator hostname remain undecided. No production listeners, DNS, firewall, Mullvad or global trust changes were made; all local storage remains on E:.
