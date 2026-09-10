# Development Linux enrollment command

The Linux command separates local preparation, certificate redemption and activation. It uses the [ordinary HTTPS transport](enrollment.md), [durable file layer](local-state.md), and the already pinned age library for encrypted software-key storage. It is not an installed enrollment service or a platform hardware keystore. The private endpoints remain loopback-only development services.

```text
portico enroll prepare --config /etc/portico/enrollment.json --secrets-fd 3
portico enroll redeem --config /etc/portico/enrollment.json --secrets-fd 3
portico enroll activate --config /etc/portico/enrollment.json --secrets-fd 3
```

The trusted launcher supplies a separate inherited read pipe at descriptor 3. It writes one strict JSON object and closes its writer. Application stdin/stdout, command arguments and environment variables are not secret-input channels. Ordinary files, terminals, sockets, wrong pipe directions and descriptors 0–2 reject. The process reopens the pipe as a separately owned pollable description; it does not change the original description's blocking mode. Input is limited to 4096 bytes and 30 seconds; cancellation discards partial input. The command emits only fixed status/error text. Never put a real password or invitation token in shell history to construct this input.

For interactive Linux use, replace `--secrets-fd 3` with `--prompt`. The [terminal input contract](terminal-unlocking.md) supplies the same fields through hidden foreground terminal entry, independently of application stdin/stdout. Choose exactly one secret source; the command never falls back from one to the other.

| Operation | Fields in the secret object | Result |
|---|---|---|
| prepare | `passphrase`, matching `confirmation` | New encrypted key/attempt file, committed before any network request |
| redeem | `passphrase`, `invitation_secret` | Validated public certificate retained in a separate protected file |
| activate | `passphrase` | Fresh TLS proof of the retained private key and an authenticated activation response |

Unknown/duplicate JSON fields reject. Prepare rejects an invitation secret; redeem and activate reject a confirmation; activate rejects an invitation secret. The passphrase must be valid UTF-8, 16–1024 bytes, without NUL or line terminators. This is an input policy, not an entropy guarantee. The bearer invitation secret is never written by the command. The launcher is responsible for protecting its input; the host administrator and OS user remain trusted.

## Approved public configuration

The configuration and every referenced certificate file must pass the protected path/ownership rules. Obtain these public values independently through the approved invitation channel. No discovery or trust on first use is performed. Version is 1; only `device` and `connector` profiles are accepted.

```json
{
  "version": 1,
  "deployment_id": "approved deployment UUID",
  "profile": "device",
  "issuer": {
    "issuer_id": "approved issuer UUID",
    "root_certificate_file": "/etc/portico/root.pem",
    "issuer_certificate_file": "/etc/portico/device-issuer.pem"
  },
  "principal_id": "approved device UUID",
  "invitation_id": "approved invitation UUID",
  "not_after": "approved whole-second UTC RFC3339 deadline ending in Z",
  "state_file": "/var/lib/portico/user/attempt.age",
  "redemption": {
    "url": "https://localhost:8443",
    "root_certificate_file": "/etc/portico/server-root.pem",
    "spki_sha256": "approved server SPKI SHA-256"
  },
  "activation": {
    "url": "https://localhost:8444",
    "root_certificate_file": "/etc/portico/server-root.pem",
    "spki_sha256": "approved server SPKI SHA-256"
  },
  "operation_timeout_ms": 5000
}
```

This is a shape example with deliberately non-operational placeholders. Provision the parent directory durably with protected ownership/modes first. Configuration cannot contain an inline private key, bearer secret or administrator profile. Deadline aliases/fractions, noncanonical state paths, malformed pins, absent trust files, identical endpoints and non-loopback endpoints reject. Every subsequent operation must match the original deployment, profile, issuer certificates, principal, invitation, exact expiry and both endpoints' URL/root/pin bindings.

## Persistence and recovery

Prepare generates a local P-256 key and random attempt UUID. A versioned, purpose-bound record contains its PKCS#8 key and approved public bindings, but no bearer secret. The record is encrypted using age's password recipient with scrypt work factor 18. Reads cap accepted work at that same factor and consume the entire authenticated stream before returning plaintext. Only one KDF operation is admitted per process, without a waiting queue; the KDF itself is synchronous. The stored file is at most 16 KiB, and decrypted attempt data is at most 8 KiB. [age API documentation](https://pkg.go.dev/filippo.io/age@v1.3.2#ScryptIdentity.SetMaxWorkFactor), [age authentication properties](https://words.filippo.io/age-authentication/).

Prepare never replaces an existing attempt. Redeem and activate never generate missing state. A failed disk operation returns no newly usable signer; reopening requires protected-file validation and file/directory sync before decryption. Losing a redemption response requires reopening and explicitly retrying the original key/attempt with the invitation secret. The issuer remains responsible for at-most-once signing and ambiguous receipt reconciliation.

The exact public certificate is stored at `state_file` plus `.certificate`, limited to 32 KiB and mode 0600. It includes the same bindings and attempt ID. Existing certificate state must match byte for byte; it is never overwritten. Activation reloads and validates the certificate against the local key, approved profile/principal/expiry and trust. A lost activation response can be retried from the retained certificate without the invitation secret. No local active flag replaces the server's live registry.

Owned mutable input, serialized-key and decrypted-state buffers are cleared. Go, JSON, TLS and age may retain internal allocations; no forensic erasure, swap/crash-dump isolation or same-user process isolation is claimed. The [version-2 resource client](client-configuration.md) can unlock this retained identity through its dedicated secret pipe or explicit terminal prompt, checking independent device trust before decryption. Resource access does not redeem, activate, replace or rewrite enrollment state. Desktop unlocking, platform custody, installed services and the remaining acceptance gates still require implementation and qualification.
