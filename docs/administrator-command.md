# Linux administrator command

`portico admin open --config /absolute/path/admin.json --prompt` connects an existing enrolled administrator identity to the native window. An inherited pipe may supply `--secrets-fd 3` instead. The sources are mutually exclusive; passwords, executable overrides and browser switches are not command arguments. Pipe input is a single strict JSON object containing `passphrase`, using the existing bounded secret-pipe reader. The foreground terminal prompt disables echo and restores terminal settings. Configuration failures return a generic message before requesting a secret.

This development command requires an existing certificate and an [encrypted administrator key](administrator-key-storage.md). Version 2 configuration enables [hardware-approved renewal](administrator-renewal.md) of that identity. Initial administrator issuance, device registration, owner creation, bootstrap finalization and recovery remain separate work. The ordinary client and enrollment profiles are unchanged.

## Protected configuration

The version 1 JSON object has these fields:

| Field | Meaning |
|---|---|
| `version` | Exactly `1` |
| `deployment_id`, `principal_id` | Approved deployment and administrator UUIDs |
| `administrators` | `issuer_id`, `root_certificate_file`, `issuer_certificate_file` |
| `identity_certificate_file` | Existing administrator leaf certificate, as one PEM certificate |
| `encrypted_key_file` | Existing administrator encrypted key file |
| `server` | Fixed HTTPS `url`, `root_certificate_file` and lowercase `spki_sha256` |
| `bootstrap_address` or `socket` | Exactly one literal loopback address and port, or canonical absolute protected local stream path |
| `state_directory` | Existing private directory owned by the process UID, mode 0700 |
| `operation_timeout_ms` | 1–5000 milliseconds |
| `session_lifetime_seconds` | 1–600 seconds, further restricted by certificate validity and clock health |

Files use the existing Linux descriptor-based protected path traversal. Unknown or duplicate JSON fields, plaintext keys, caller clock estimates, alternate executables, environments and browser switches are rejected. Configuration binds the current administrator certificate to its approved principal and trust before unlocking. Unlocking separately checks the encrypted record's authority and key binding. The server name and pin stay fixed while the selected loopback or local stream supplies transport; configuration does not establish authorization for a management resource.

Version 2 retains these fields and requires a `renewal` object containing its own `server` and exactly one `bootstrap_address` or `socket`. It must select a different transport endpoint from ordinary administration. Each endpoint has independent fixed root and SPKI verification; neither is supplied by the renderer. Version 1 rejects the new object and retains its earlier behavior. The original certificate remains the independently configured identity anchor. Version 2 can verify an expired predecessor's signed scope when loading a later journal entry; the selected certificate and native signer must still pass current validity and live server authorization.

The command creates an owned mode-0700 `credentials` child inside the existing private state directory and holds a separate exclusive directory lock. Its bounded mode-0600 `identity.json` stores public certificates, renewal requests and review state. It never contains a private key or passphrase. Configuration, authority fingerprints, original certificate and both network routes are bound to the record. Updates check the expected prior bytes, write and flush a fresh inode, atomically publish it and flush the directory. Unsafe files, ownership, links, changed permissions or a second writer are rejected. A failed commit disables that handle until reopening and fresh durability checks resolve whether publication occurred.

The native signer stays in Go. The command clears its passphrase input after the synchronous unlock, before the window runs, and also on failure. Go and cryptographic-library allocations still prevent a forensic-erasure claim. It closes the bridge, revokes the signer and releases private state on success, failure or cancellation. Cancellation during the KDF is observed after the bounded synchronous unlock; no window starts afterward.

## Installation boundary

The command uses fixed paths `/usr/lib/portico-admin/electron/electron` and `/usr/lib/portico-admin/app/main.cjs`. The app directory also requires `channel.cjs` and `shell.cjs`. Configuration cannot select another executable or entry point. The entire installation tree is inspected through directory descriptors before unlocking: protected ancestors, root or effective-UID ownership, no group/other writes, no symbolic links, singly linked regular files, no device/socket/FIFO members, at most 512 entries, at most 768 MiB of file sizes and bounded directory depth. The executable must have its owner execute bit. Special modes are rejected except the exact root-owned 4755 `electron/chrome-sandbox` helper. Only an installer may establish that helper; this command never changes ownership or permissions.

The existing private state directory is locked exclusively for the whole session. A second cooperating administrator process fails before unlocking a key. The command does not create that parent or repair existing permissions, and deletes no stale lock. Only the version-2 credential child and fresh files described above are created. Root and the effective UID remain trusted, including against replacement after inspection. This check is not a package signature, complete dependency review or OS process sandbox. The browser retains the existing native transport and renderer restrictions described in [native administration](native-administration.md).

A separate [administrator development package](administrator-package.md) prepares the fixed Electron/application tree. Source `1ccbe15` passed hosted Arch install/remove and the unmodified installed-command/window test with the real kernel clock. The Arch CLI package still does not install that tree itself. A supported signed installer, packaged runtime review/fuses and real administrator enrollment remain unfinished. The command fails closed until the required protected files exist; this work does not install services or modify the developer host.

## Qualification

Portable tests cover configuration binding, rejected authority/launch overrides, the exact command surface and resource cleanup through startup failures and cancellation. Linux tests cover installation members, symlink/hardlink/FIFO and permission rejection, directory-lock exclusion and reacquisition. A Linux integration test loads protected configuration, reopens an actual encrypted key, authenticates a real pinned TLS request, verifies signer revocation and reacquires private state after return. Its native child is substituted by the request driver; actual window execution remains separately qualified by the native browser suite. Neither that substitution nor a virtual key establishes a complete installed owner ceremony.

The first integration fixture omitted two required HTTP security headers and was rejected. The fixture now sends those headers; production response requirements are unchanged. Final outcomes and source hashes are recorded in [command evidence](phase-7-administrator-command-evidence.json). These component checks do not change the canonical seven implemented and 84 planned acceptance cases.
