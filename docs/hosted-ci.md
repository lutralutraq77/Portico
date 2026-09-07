# Hosted CI execution record

Date: 2026-09-07. Repository: [private lutralutraq77/Portico](https://github.com/lutralutraq77/Portico). Review: [draft PR #1](https://github.com/lutralutraq77/Portico/pull/1).

The implementation was uploaded and hosted workflows were triggered for commit `22538d86118263f91c7aa0adf552321502174a46`.

| Workflow | Run | Observed outcome |
|---|---|---|
| Repository quality (Ubuntu/Windows matrix) | [34135948306](https://github.com/lutralutraq77/Portico/actions/runs/34135948306) | Failed before either job started |
| Dependency review | [34135948368](https://github.com/lutralutraq77/Portico/actions/runs/34135948368) | Failed; no executed steps returned |
| CodeQL | [34135948567](https://github.com/lutralutraq77/Portico/actions/runs/34135948567) | Failed; no executed steps returned |

The quality run annotations explicitly report an account billing problem: recent payments failed or the spending limit needs increasing. This is a GitHub account prerequisite, not a test assertion failure. No hosted test, CodeQL analysis or dependency review can be reported as passed.

The account owner needs to resolve GitHub billing/limits and then rerun the latest PR checks. No payment, spending-limit change, public visibility change or security-setting reduction was made. Further platform or private-repository feature restrictions may become visible only after runners can start.

Local verification already passed on Windows and on a real Linux kernel in an isolated QEMU VM; see [Phase 2 report](phase-2-report.md). The local Linux run does not replace the pending Ubuntu-hosted race and quality checks.

The PR remains a draft and has not been merged. No supported release or deployment was published.

