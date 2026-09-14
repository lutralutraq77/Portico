# Interactive Linux unlocking

Append `--prompt` to an enrollment command or a version-2 resource-client command to enter its secrets at the foreground controlling terminal:

```text
portico enroll prepare --config /etc/portico/enrollment.json --prompt
portico enroll redeem --config /etc/portico/enrollment.json --prompt
portico enroll activate --config /etc/portico/enrollment.json --prompt
portico client catalog --config /etc/portico/client.json --prompt
portico client connect --config /etc/portico/client.json --resource UUID --revision N --prompt
```

These examples require approved configuration and provisioned development services. UUID and N are placeholders. Connect still requires application input/output pipes. Its prompts and secret input use the controlling terminal independently of those pipes; prompts never enter the resource payload. Enrollment and catalog retain their normal status/JSON output.

| Operation | Hidden input, in order |
|---|---|
| prepare | New passphrase; matching confirmation |
| redeem | Unlock passphrase; invitation secret |
| activate | Unlock passphrase |
| catalog or connect | Unlock passphrase |

Finish each entry with Enter. Passphrases must satisfy the existing 16–1024 byte UTF-8 policy; the invitation secret must be the approved 43-character token. Canonical terminal editing is available, including Unicode character erasure. Input conversion that strips high bits or changes letter case is disabled during entry. Empty entries, NUL, invalid UTF-8, overlong lines and terminal EOF reject. Limits are in bytes, and the resulting secret object must also fit the existing 4096-byte bound; a pair of heavily escaped maximum-length passphrases can exceed that bound.

## Terminal ownership and cancellation

The implementation opens the fixed `/dev/tty` path as its own pollable description and requires a character device whose foreground process group matches the caller. It rejects a missing controlling terminal, background execution, concurrent prompting in one process, and unsupported platforms. There is no automatic fallback to an inherited secret pipe. `--prompt` and `--secrets-fd 3` are mutually exclusive, exact command suffixes. No command argument or configuration value can supply a terminal path, prompt label or password. [Linux controlling terminal documentation](https://man7.org/linux/man-pages/man4/tty.4.html).

Echo is disabled before any prompt appears. Each invocation has a two-minute bound covering all its terminal entries, or the caller's earlier deadline. Ctrl+C and the binary's SIGTERM cancellation handler stop input. The terminal's EOF key rejects even after a partial line. Typed quit and suspend controls are disabled during entry. Queued input is discarded before restoring every saved terminal attribute on the handled success/error/cancellation paths; failed restoration rejects the result. The owned descriptor and its cancellation callback are joined and closed. [Linux terminal attributes](https://man7.org/linux/man-pages/man3/termios.3.html), [Go file deadlines](https://pkg.go.dev/os#File.SetDeadline).

The terminal timeout covers input, not the subsequent synchronous password KDF. The caller and OS user must control the terminal and its session. An uncatchable termination such as SIGKILL or SIGSTOP cannot execute cleanup; no restoration guarantee is made for those events or a lost terminal. Mutable owned input buffers are cleared, but Go and cryptographic libraries can retain internal allocations. This interface does not establish forensic erasure, same-user process isolation, a desktop unlock agent or hardware key custody.

The [enrollment contract](enrollment-command.md) and [resource-client contract](client-configuration.md) retain their protected-file, trust, persistence and live-authorization rules. Prompting changes only how those commands receive secrets. The [terminal qualification report](phase-6-terminal-report.md) distinguishes exercised paths from pending qualification.
