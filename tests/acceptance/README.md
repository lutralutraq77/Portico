# Runtime security acceptance backlog

The canonical cases are in [the acceptance plan](../../ACCEPTANCE_TEST_PLAN.md).
The machine-readable manifest records the same 91 case IDs and their earliest phases.

Seven cases have complete executable scenarios: AUDIT-01 process crashes; CONN-01 two-connector hosting/socket isolation; CONN-03 cross-connector control scope; CONN-04 active connector revocation, restart and replay; PROTO-03 independent stream lifecycles; PROTO-04 malformed inputs and actual HTTP/2 resets; and PROTO-05 backpressure, quotas and reconnect floods. The remaining 84 cases are planned. [Isolation evidence](../../docs/phase-5-isolation-report.md) [lifecycle evidence](../../docs/phase-5-lifecycle-report.md) [overload evidence](../../docs/phase-5-overload-report.md) and [hostile protocol evidence](../../docs/phase-5-protocol-report.md) identify exact sources and runs. Socket/process scenarios execute only in the guarded NIC-less Linux guest; exclusion or skips on other hosts do not qualify them. Partial domain evidence does not establish other complete scenarios. Foundation tests live in the Go packages and scripts; their results are reported separately.

Change a runtime case to implemented only with its actual executable test path. Mark passing only in a run-specific evidence report, never as a permanent property of this manifest.
