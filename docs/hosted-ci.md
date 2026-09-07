# Hosted CI execution record

Date: 2026-09-07. Repository: [private lutralutraq77/Portico](https://github.com/lutralutraq77/Portico). Review: [draft PR #1](https://github.com/lutralutraq77/Portico/pull/1).

The implementation was uploaded and hosted workflows were initially triggered for commit `22538d86118263f91c7aa0adf552321502174a46`. After repository cleanup, all three PR workflows for commit `f1957e89ba9c982f3ff74febf7969e5e6737609a` were retried on 2026-09-07 at approximately 15:09 UTC (16:09 Europe/London). The latest observed attempts are recorded below.

| Workflow | Run | Observed outcome |
|---|---|---|
| Repository quality (Ubuntu/Windows matrix) | [34136182366, attempt 2](https://github.com/lutralutraq77/Portico/actions/runs/34136182366) | Failed before either job started |
| Dependency review | [34136182290, attempt 2](https://github.com/lutralutraq77/Portico/actions/runs/34136182290) | Failed; no executed steps returned |
| CodeQL | [34136182355, attempt 2](https://github.com/lutralutraq77/Portico/actions/runs/34136182355) | Failed; no executed steps returned |

The fresh quality run annotations still explicitly report an account billing problem: recent payments failed or the spending limit needs increasing. Windows job `101789738817` and Ubuntu job `101789739127` both returned no executed steps. This is a GitHub account prerequisite, not a test assertion failure. No hosted test, CodeQL analysis or dependency review can be reported as passed. Repository cleanup has not cleared the observed restriction.

The account owner needs to resolve GitHub billing/limits and then rerun the latest PR checks. No payment, spending-limit change, public visibility change or security-setting reduction was made. Further platform or private-repository feature restrictions may become visible only after runners can start.

Local verification already passed on Windows and on a real Linux kernel in an isolated QEMU VM; see [Phase 2 report](phase-2-report.md). The local Linux run does not replace the pending Ubuntu-hosted race and quality checks.

The PR remains a draft and has not been merged. No supported release or deployment was published.
