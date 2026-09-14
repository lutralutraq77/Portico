# Phase 5 connector isolation evidence

Source 160911ce5f602c142f1834d5bdea06756fdc7059 adds complete executable scenarios for CONN-01 and CONN-03 and passed full local Windows, full isolated Linux and hosted Windows/Ubuntu checks. A final test-only refinement at 48b991b9c5688fb531987618cea43b8022f08b10 requires explicit authenticated relay rejection and passed the focused Linux suite. The canonical manifest now links three implemented cases, including the existing AUDIT-01, and retains 88 planned cases. Phase 5 and the complete fifteen-phase objective remain in progress. [Delivery ledger](delivery-status.md), [manifest](../tests/acceptance/manifest.json), [test source](../internal/controller/connector_isolation_test.go), [machine-readable evidence](phase-5-isolation-evidence.json), [draft PR 4](https://github.com/lutralutraq77/Portico/pull/4).

## Complete scenario coverage

CONN-01 separately enrolls and activates connectors A and B. A reaches its assigned TCP resource with a live HostBinding. B cannot bind the relay under A's identity, obtain A's hosting advertisement, serve A's resource or serve its own locally configured resource without a HostBinding. The hostile device opens authenticate the actual inner TLS leaf but bypass the honest client's online preflight, so the connector server must enforce the denial itself. The spoofed Bind is also observed for forbidden admission to the pairing queue; merely waiting for a local timeout is not sufficient evidence.

After adding B's independent HostBinding, B reaches its own exact resource through the same server and transport. Disabling A's binding prevents a fresh hostile open through A's still-running server. The destination observes exactly the two authorized connections and their distinct payloads; every connection closes, and workload/carrier workers and stream handles join. These are accepted-socket and application-byte observations, not packet-capture claims about SYNs or independent operating-system egress confinement.

CONN-03 uses B's actual mTLS control client to request A's resource, a different revision, B's genuinely superseded revision and a nonexistent future revision. No denied request creates a session. B cannot activate, renew or close A's session, acknowledge A's cancellation, or retrieve it through a selected cancellation poll. A's durable session state, lease sequence/deadline, cancellation and receipt counts remain unchanged by each denied mutation. Both connectors complete their own valid authorization, activation, renewal and closure lifecycles. Audit verification succeeds. The test evaluates controller scope, as required by the canonical case; local physical socket confinement remains separate.

The production implementation is unchanged. The shared enrollment test helper now truncates certificate expiry to whole seconds, matching the existing invitation contract when the workload fixture uses a live clock. It does not change the store clock or weaken enrollment validation.

## Run-specific verification

The full NIC-less guest passed 141 top-level tests, 492 subtests and 36 seeds across seven fuzz targets, with one intentional issuer subprocess-helper skip. Both new isolation scenarios executed in this run. The focused workload run passed 38 top-level tests, 107 subtests and two seeds for one fuzz target, with no skips. Linux 6.18.35-0-virt ran under pinned QEMU 11.1.0 TCG, without a NIC or host filesystem shares. These guest tests are not race instrumented. Their markers are PORTICO_LINUX_ALL_PASS and PORTICO_LINUX_WORKLOAD_PASS respectively.

| Artifact | SHA-256 |
|---|---|
| Full Windows check at 160911c | 2E3B9A5FAA47E9F02F88DF2241560E7C04D13CC26715658B242DACC375A5DD4C |
| Full Linux serial log | 0350405D92CB6C52CCDEAB6503A603CD4850A9A3EB513FB3023A2A158BC51DEE |
| Focused Linux serial log | BFC5E69B57E4795F1A6F095CCFABE6AC048204C79785C4E9FBBB3B1D3795EF90 |
| Final focused Linux log at 48b991b | 0EF6B79E3AAA3618C018C4867AD8CD83F7E999C87C962E59EAF49A1507B7CA1D |
| Initial failed focused log | 38F8EB193FE5BD0E5B2CC671557F073B02D0514F1870A4059FB77F5CD8D681F7 |

Passing logs and summaries are retained in work/reports/phase-5-isolation-160911c. The initial failed log and its exact new test source are in work/reports/phase-5-isolation-initial. The initial second-connector enrollment was rejected before socket testing because its live-clock expiry included fractional seconds. The corrected fixture and strengthened Bind assertion then passed focused and full Linux runs. No production check was relaxed.

The full Windows script ran without skip flags. Both Go modules passed unit/race tests, all seven bounded fuzz targets, vet/static analysis, package/tool vulnerability scans and positive controls, source-secret/workflow/documentation checks, development builds, reproducibility and SBOM/provenance checks. Workload framing executed 91,589 fuzz inputs. Scans found no affected imported packages; one advisory in required modules outside those imports remains visible. The separately reported guest-only skips do not qualify destination sockets on Windows or ordinary hosted Ubuntu.

Source 160911c also passed [hosted quality](https://github.com/lutralutraq77/Portico/actions/runs/34178533304), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34178533409) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34178533342). Windows job 101912667012 and Ubuntu job 101912667294 both completed the full check and evidence upload. Their raw logs are in the same local archive. Later commits require their own hosted status checks.

Final review found that the carrier client's generic error could hide its internal opening timeout. Source 48b991b changes only that guest test assertion: it sends the spoofed Bind using raw authenticated gRPC, requires the server's PermissionDenied status, confirms B passed the real identity admission callback exactly once, and rejects any pairing-queue admission. The final focused guest run passed 38 top-level tests, 107 subtests and two fuzz seeds with no skips; its archive is work/reports/phase-5-isolation-48b991b. The final test-source SHA-256 is BADAB01A626C34BB8509E41A14F840AA914875DF7E639D7FACC2011489E8BC7C. Full-suite evidence above remains attributed to 160911c; the assertion refinement does not change production code or CONN-03. Final PR-head hosted checks are tracked separately in PR 4.

The full Linux run also retained the real command's SIGTERM/SIGKILL/restart checks. That separate fixture supplies synthetic kernel synchronization metadata only inside the disposable guest and restores its original unsynchronized state; it proves no upstream clock accuracy. Existing revocation and withheld-renewal observations were 181.451732 ms and 1,950.763768 ms respectively. These fixture measurements do not accept Q05, physical suspend or hostile scheduling.

## Remaining work

At this isolation checkpoint CONN-04 still needed combined active connector disable/certificate revocation, process restart and old hosting/session replay. The later [lifecycle report](phase-5-lifecycle-report.md) records that scenario and PROTO-03. Complete protocol load/reset scenarios, installed service/controller/client packaging, host time-service qualification, independent network isolation, physical keys and the remaining platform/application phases remain open. Hardware-key models and the private sign-in hostname remain undecided. All local source, builds, caches and evidence stay on E:.
