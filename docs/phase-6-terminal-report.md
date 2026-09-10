# Phase 6 interactive terminal qualification

The development Linux command accepts `--prompt` for enrollment and encrypted resource-client identities. It uses a bounded foreground controlling terminal with echo disabled, separate from application pipes. Its [command contract](terminal-unlocking.md) describes limits, cancellation, cleanup and the remaining platform boundary.

## Verification in progress

The first focused NIC-less Linux guest passed fifteen real-PTY input cases, the invalid-context/concurrent-admission checks and the existing five secret-pipe cases. It emitted `PORTICO_LINUX_TERMINAL_FOCUSED_PASS`; the preserved log is `work/reports/phase-6-terminal-input/runtime.log`. This candidate predates the additional input-conversion normalization and expanded cases. It does not qualify those later changes.

Native Windows CLI/client unit packages passed after the command-surface refactor, and the Linux CLI/controller test binaries compiled. Windows excludes Linux terminal execution. All twenty-one expanded real-PTY cases passed in the second focused guest. The actual enrollment-to-resource command scenario is still under test; hosted checks for the new terminal source are pending.

The expanded component suite uses real disposable PTYs to check hidden UTF-8 input, line editing, inherited input conversion, entry and encoded-object bounds, invalid bytes, EOF, cancellation, Ctrl+C, missing controlling terminals and background process groups. It checks exact terminal attribute restoration and discarded abandoned input while a gated fixture process retains its terminal session. The process scenario exercises the actual binary with controlling-terminal input and distinct application pipes, through enrollment, activation, resource transfer and certificate revocation.

All terminal fixtures require the existing isolated-guest marker and loopback-only interfaces. Guest init mounts private devpts and the archive includes `/dev/tty`; these are disposable guest devices. The process scenario continues to use explicitly synthetic guest clock metadata. No host terminal, host networking or host clock is modified.

## Scope

This work does not complete platform key custody, a desktop/browser workflow, Arch installation, physical lifecycle tests or real administrator-key recovery. The acceptance manifest remains seven implemented and 84 planned cases. Subsequent evidence must identify the tested source and must not relabel earlier passes as final-source qualification.
