# Phase 5 carrier progress

Implementation revision `c77fc375d25b3a6d30a4df2d72440c873e20614d` adds the bounded carrier and passes the full local check suite and isolated Linux runtime tests. Phase 5 and the full fifteen-phase objective remain incomplete. [Draft PR 4](https://github.com/lutralutraq77/Portico/pull/4) is stacked on Phase 4. The [carrier contract](carrier-protocol.md) defines the implemented boundary; [machine-readable evidence](phase-5-evidence.json) records exact sources, counts and artifact hashes.

## Implemented behavior

- Generated gRPC messages pair authenticated device and connector streams. Real TLS peer certificates, pinned profiles, live registry admission and quotas across connections govern entry. A connector can bind only itself. The client uses private roots, standard hostname verification and an SPKI pin; identity-like headers are ignored.
- Standard inner mutual TLS authenticates the device and the exact expected connector, and supports large bidirectional traffic and TLS half-close. The connector DNS SAN and issuer profile binding preserve standard server-name verification without global DNS or trust changes.
- A separate cancellation Watch is bound to the same actual certificate and random stream ID. Both watches must exist before payload forwarding. This fixes an observed failure where terminal status stayed behind unread DATA and a local pump survived until its long call timeout. Blocked consumers now close on peer/client disconnect, relay shutdown, context cancellation and simultaneous close. Closing one logical stream preserves another using the same outer connection.
- Strict message bounds, deadlines, per-principal/global stream quotas, local Client quotas, connection limits and bounded workers reject malformed messages and abandoned or excessive operations. Pinned generator checks reject stale generated code. The new protobuf fuzzer exercises decoding, meaning-preserving round trips and future-field rejection.

The integration fixture composes admission with the real controller registry and activated identities; production service composition is not implemented. The carrier itself cannot authorize a resource or open a destination socket.

## Verification

The complete Windows scripts/check.ps1 run passed without skip flags: both modules' unit/race tests, six bounded fuzz targets, vet/static analysis, dependency/secret/workflow/documentation checks, scanner positive controls, four development binaries, byte-identical native rebuilds and SBOM/provenance checks. A separate imported-package vulnerability scan of the carrier also passed. Scans retain one unimported module advisory rather than suppressing it; no reachable application or imported issuer/tool/carrier package vulnerability was reported.

All 14 carrier integration test groups and their 44 subtests ran through real loopback sockets. A focused integration coverage run measured 93.5% of carrier statements. The full suite's per-package coverage file does not aggregate dependency coverage from tests in other packages; it must not be substituted for that focused measurement. Coverage is not a completeness or security claim.

The final full check's carrier fuzzer executed 14,453 inputs. It also passed the CLI, destination, PKI, WebAuthn and control-JSON fuzz targets. The Linux VM passed 80 top-level tests, 265 subtests and 34 fuzz seeds across six fuzz targets, with one intentional subprocess-helper skip. All 14 carrier groups passed there, including stalled-reader cancellation and independent stream survival. The guest ran kernel 6.18.35-0-virt under QEMU 11.1.0 TCG, with guest loopback, no NIC, no host filesystem shares and no race instrumentation. Windows race tests ran separately.

On implementation head c77fc37, hosted [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34160979093) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34160979204) passed. Hosted [Windows/Ubuntu quality](https://github.com/lutralutraq77/Portico/actions/runs/34160979103) was still running when this report was created. A later documentation head needs its own hosted result; historical success is not evidence for future changes.

## Remaining work

Next implement the live client check of the actual inner connector leaf, authenticated hosting snapshots, the exact workload proxy, activation before application bytes, request-start-anchored leases, and durable controller cancellation delivery with receipts after actual socket closure. Tests must observe real destination connection counts, authority changes, delayed responses, controller outages, restart and hostile-load resource bounds. Transport Watch closure is not controller revocation delivery or an accepted revocation SLA; Q05 remains open.

The development CLI still reports version 0.4.0-dev and exposes version/help. There is no deployed connector system or supported client in this checkpoint. Linux/Arch and Windows application/key-store integration, the dashboard/bootstrap, Android, deployment isolation, Mullvad/DNS coexistence, SSH CA, signed updates, physical hardware/recovery qualification and independent security review remain in the full scope. Hardware models and the private administrator hostname are still undecided, as the owner stated.

The canonical acceptance manifest remains 91 cases: AUDIT-01 implemented and 90 full scenarios planned. Component TLS and cancellation tests do not replace socket authorization, hardware, browser or platform evidence. All local project storage remains on E:.
