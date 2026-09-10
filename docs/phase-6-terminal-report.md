# Phase 6 interactive terminal qualification

The development Linux command accepts `--prompt` for enrollment and encrypted resource-client identities. It uses a bounded foreground controlling terminal with echo disabled, separate from application pipes. Its [command contract](terminal-unlocking.md) describes limits, cancellation, cleanup and the remaining platform boundary.

## Hosted qualification

Runtime source `0c3972279c889cf2e5cb2384d0ff784f4b70fb2b` passed all hosted workflows: [Windows/Ubuntu quality](https://github.com/lutralutraq77/Portico/actions/runs/34489343881), [complete isolated Linux runtime](https://github.com/lutralutraq77/Portico/actions/runs/34489343896), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34489343737) and [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34489343722). The tested merge `75fd2d3c4f786f37e506b51bf3a80f6c481dfaaa` and source share tree `91a888faf6e47aa906c8de89f29b2cf09d96eae0`, verified from Git objects.

The complete guest passed 197 top-level tests and 940 subcases, with zero failures and one expected `TestIssuerProcessFixture` helper skip. All 21 terminal cases passed in 2.44 seconds. The actual prompt enrollment/resource/revocation scenario passed in 70.42 seconds; the retained descriptor-3 variant passed in 67.53 seconds. The suite emitted `PORTICO_LINUX_ALL_PASS`.

Downloaded artifact `10157674589` matched GitHub's ZIP SHA-256 `e1fca0b9c50df013d672f1c1aab42079f3589259063c2fb3b45194f2e45f139c`. The extracted runtime log hash is `d1f27abf578f2fe1bc6d4dd4092ce8b064ecbdb6c3a846c0cf3b5aece6ff74fe`. Its environment records QEMU 11.1.1 TCG, two CPUs, 1536 MiB, no NIC and no host shares. [Machine-readable evidence](phase-6-terminal-evidence.json) identifies the source and preserved artifacts.

## Local qualification and diagnosis

The first focused NIC-less Linux guest passed fifteen real-PTY input cases, the invalid-context/concurrent-admission checks and the existing five secret-pipe cases. It emitted `PORTICO_LINUX_TERMINAL_FOCUSED_PASS`; the preserved log is `work/reports/phase-6-terminal-input/runtime.log`. This candidate predates the additional input-conversion normalization and expanded cases. It does not qualify those later changes.

Native Windows CLI/client unit packages passed after the command-surface refactor, and the Linux CLI/controller test binaries compiled. CLI/client race tests then passed in 56.889 and 8.917 seconds. Windows/Linux vet and Linux static analysis passed. Windows excludes Linux terminal execution. The native log hash is `0f9d5fa766608cebf29ca6a5434224bd95e84d09fa35d04ee54e3beda39484ae`.

All twenty-one expanded real-PTY cases passed in the second local focused guest. The actual enrollment-to-resource command scenario passed seven subcases but failed its final transfer check with EOF before delivery, so that complete local run failed. The later hosted full-suite pass does not turn this local result into a pass. A local rerun with additional test diagnostics is in progress; its result and the cause of the first local failure remain unresolved.

The failed candidate is source `0c3972279c889cf2e5cb2384d0ff784f4b70fb2b`. Its runtime log is preserved at `work/reports/phase-6-terminal-client/runtime.log`, SHA-256 `74b7fb2abe4e200e44f90699e7a68634aad6a76c3d74098695cb8a534deb42aa`. No production timeout or authorization rule has been relaxed in response. Subsequent diagnostics report destination, authority and carrier counts when the first transfer fails.

The expanded component suite uses real disposable PTYs to check hidden UTF-8 input, line editing, inherited input conversion, entry and encoded-object bounds, invalid bytes, EOF, cancellation, Ctrl+C, missing controlling terminals and background process groups. It checks exact terminal attribute restoration and discarded abandoned input while a gated fixture process retains its terminal session. The process scenario exercises the actual binary with controlling-terminal input and distinct application pipes, through enrollment, activation, resource transfer and certificate revocation.

All terminal fixtures require the existing isolated-guest marker and loopback-only interfaces. Guest init mounts private devpts and the archive includes `/dev/tty`; these are disposable guest devices. The process scenario continues to use explicitly synthetic guest clock metadata. No host terminal, host networking or host clock is modified.

## Scope

This work does not complete platform key custody, a desktop/browser workflow, Arch installation, physical lifecycle tests or real administrator-key recovery. The acceptance manifest remains seven implemented and 84 planned cases. Subsequent evidence must identify the tested source and must not relabel earlier passes as final-source qualification.
