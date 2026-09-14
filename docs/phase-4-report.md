# Phase 4 resource policy progress

The controller policy engine, private TLS API component and immutable hardware-approved policy previews are implemented. Full Phase 4 acceptance remains open until connector tests observe actual destination sockets; the active objective still includes all fifteen phases.

Implementation commit `fe26332680bb07c5b1916df2d6f126d46f3afb4e` passed scripts/check.ps1 without skip flags on Windows and scripts/test-linux.ps1 in the isolated Linux VM. [Machine-readable evidence](phase-4-evidence.json) records coverage, fuzz counts, build/SBOM hashes and log hashes. [ADR-005](../ADR-005-resource-policy-boundary.md) and the [API contract](policy-api.md) define the new boundary.

## Observed behavior

- Authorization derives one TCP destination from the stored current resource revision. It requires the exact device grant, independent connector HostBinding, verified certificate profiles and current registry authority. Quotas are allocated atomically; an eight-request race at a one-session limit admits exactly one.
- Activation and renewal require the original connector certificate and sequence, then recheck all live authority and the original grant/binding. Expired, revoked, changed, restarted or closed sessions cannot reactivate; renewing never extends their original absolute deadline.
- Administrator changes use the stored server preview and a fresh required-UV WebAuthn assertion after two factors have been registered and tested. Mutated input cannot change an already approved endpoint. Replay/concurrent completion commits once. Normal session traffic preserves preview validity; changes to authority invalidate it.
- Private HTTP tests use real mutual TLS, strict body decoding and separate profile allowlists. Destination/grant overrides, duplicate/case-alias fields, malformed bodies, forged identity headers, wrong routes/profiles/Host/Origin and revocation on a reused TLS connection reject.
- Schema 4 separates policy revision from audit traffic, starts existing administrators at a usable revision and removes old challenges during upgrade. Tests found and corrected the zero-initial-revision issue before committing. Failed migration or audit writes roll back the entire change, including factor counters and challenge consumption. Snapshots remove previews and close authorized sessions without revoking the live source store.

## Verification

The full Windows suite passed unit, race, bounded fuzz, vet, static analysis, package/symbol vulnerability scans, secret scans, workflow and documentation checks. Both scanner positive controls detected their deliberately unsafe fixtures. Four Windows/Linux application and issuer binaries built; native rebuilds were byte-identical. SBOM checks verified issuer binary hashes and retained local-module provenance.

Windows statement coverage: controller 78.4%, control JSON 78.6%, PKI 90.1%, administrator verification 81.1%, issuer adapter 77.9%, issuer service 77.7%. The control JSON fuzz run executed 84,575 inputs. Coverage and fuzz counts describe exercised code, not security completeness. Scans found no reachable application or imported issuer/tool package vulnerabilities; one unimported module advisory remains visible without suppression.

The Linux VM passed 62 top-level tests, 203 subtests and 26 fuzz seeds on kernel 6.18.35-0-virt under QEMU 11.1.0 TCG. Its subprocess helper has one intentional skip outside child mode. The guest used loopback only, no NIC and no host filesystem shares. This VM run was not race-instrumented; Windows race tests passed separately.

Hosted [quality](https://github.com/lutralutraq77/Portico/actions/runs/34158541441) and [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34158541393) were running when this report was created; [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34158541367) had passed. These links describe the implementation commit, not future branch heads. [Draft PR 3](https://github.com/lutralutraq77/Portico/pull/3) is stacked on the unmerged Phase 3 PR; current-head checks are visible there.

Subsequent verification: the Phase 4 documentation head `1a4332095eb4b9c4975bbe6e712301a8468738f6` passed hosted [Windows/Ubuntu quality](https://github.com/lutralutraq77/Portico/actions/runs/34158651389), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34158651399) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34158651507). These results were rechecked before continuing Phase 5; they do not qualify later carrier changes.

## Remaining scope

The main executable remains a development version/help command. There is no deployed controller/client/connector system, public listener, finished dashboard or supported release. Real socket proxying, cancellation delivery/acknowledgments, request-anchored leases and platform enforcement follow in Phase 5 and later phases. Administrative tests use signed virtual authenticators and isolated .test origins; physical keys, actual sign-in hostname, browser/native isolation and recovery remain unqualified.

AUDIT-01 remains the only fully implemented case in the 91-scenario manifest; 90 full scenarios remain planned. The new tests contribute component evidence to them without replacing their socket, browser, hardware or platform requirements. All source, caches, logs and binaries remain on E:. See the [complete delivery ledger](delivery-status.md) for the full remaining objective.
