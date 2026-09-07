# Runtime security acceptance backlog

The canonical cases are in [the acceptance plan](../../ACCEPTANCE_TEST_PLAN.md).
The machine-readable manifest records the same 91 case IDs and their earliest phases.

AUDIT-01 is implemented with a process-crash test; the remaining 90 cases are planned. Partial domain evidence for other audit cases is recorded without claiming their complete scenarios pass. No fake implementation or empty test body stands in for certificate, policy, network, recovery or hardware-key proof. Foundation tests live in the Go packages and scripts; their results are reported separately.

Change a runtime case to implemented only with its actual executable test path. Mark passing only in a run-specific evidence report, never as a permanent property of this manifest.
