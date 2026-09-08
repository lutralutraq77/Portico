# Runtime security acceptance backlog

The canonical cases are in [the acceptance plan](../../ACCEPTANCE_TEST_PLAN.md).
The machine-readable manifest records the same 91 case IDs and their earliest phases.

AUDIT-01 has a process-crash test. CONN-01 has a two-connector hosting/socket test and CONN-03 exercises cross-connector control requests with actual separate TLS identities. The remaining 88 cases are planned. [Connector isolation evidence](../../docs/phase-5-isolation-report.md) identifies the exact source and runs; CONN-01 executes only in the guarded NIC-less Linux guest and is explicitly skipped elsewhere. Partial domain evidence does not establish other complete scenarios. Foundation tests live in the Go packages and scripts; their results are reported separately.

Change a runtime case to implemented only with its actual executable test path. Mark passing only in a run-specific evidence report, never as a permanent property of this manifest.
