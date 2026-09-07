# ADR-004: restricted issuer, administrator factors and recovery archives

Status: implemented for isolated development qualification. Physical hardware, stable browser transport and production recovery remain open gates. The owner has explicitly left the key models and private hostname undecided; all origins and authenticators in tests are fixtures.

## Issuer boundary

Use Smallstep certificates v0.30.2 in a separate Go module and executable. The controller imports a small HTTPS/JWT adapter, not the CA implementation. The service uses Smallstep's embedded authority, JWK provisioner, signer and durable bbolt token database. It does not install the stock HTTP router. Only POST /1.0/sign exists, behind TLS 1.3 and a separately trusted, pinned controller client key. The command permits loopback listeners only. No service was deployed by this change.

The controller signs a 60-second ES256 provisioning token using go-jose v4.1.5. The token includes the attempt UUID, deployment, issuer, principal, profile, exact certificate interval, exact identity URI and Smallstep's cnf.x5rt#S256 CSR fingerprint. The service verifies the signature, exact audience, deadline and local issuer/profile binding. It independently parses the empty proof-only CSR and checks its fingerprint. The client cannot supply a template, lifetime override, SAN or alternative enrollment protocol. The CA template supplies the empty subject, fixed usages, URI and non-CA constraints; the service supplies approved times. Both sides validate the resulting certificate with the strict Portico validator.

Provisioning tokens are consumed durably before signing; only their hashes are retained. Successful verified results have durable public receipts, available only to a local operator by attempt ID. A crash before the receipt exists remains uncertain: do not re-sign or invent a result. Quarantine/revoke the attempt and use explicit reconciliation or a new approved enrollment. No automatic retry or alternate renewal route exists. The issuer database refuses reassignment to another deployment, issuer, profile or provisioner key. Planned CA rotation needs its own controlled migration.

Ordinary same-key renewal goes through the controller's existing authority rechecks and this same constrained signing path. An administrator certificate has a distinct `administrator` URI profile and a separately pinned intermediate/registry. It cannot enter the ordinary resource-authentication registry. Issuer leaves have a 24-hour absolute maximum; the controller's approved interval can be shorter. This development cap is not a finalized administrator lifetime policy.

## Administrator boundary

The server components require a completed TLS 1.3 handshake with a registered administrator certificate. Every action rechecks the current device, owner, certificate and pinned issuer. Bootstrap registration is a trusted local operation with a ten-minute window for the first two factors; completion checks the window again. No anonymous bootstrap endpoint or browser bridge was added.

go-webauthn v0.18.0 verifies WebAuthn registration/assertion signatures, RP/origin, challenge, ownership and required presence/user verification. Portico additionally requires packed certificate attestation, nonzero allowlisted AAGUIDs, an explicit attestation root chain, no backup-eligible/synced credential, and no counter rollback warning. Local attestation policy expires within 90 days. Counter-zero authenticators do not provide clone detection. Vendor status updates and actual hardware support must be qualified before deployment; attachment hints alone are not trust.

SQLite schema 3 stores public factor records and immutable operations with a server challenge, administrator ID, administrator certificate hash, operation hash, policy generation and two-minute expiry. The ceremony also binds the exact origin/attestation-policy configuration digest. A successful assertion updates its counter, consumes the challenge, applies exactly the stored action and appends audit events in one transaction. Policy/configuration changes invalidate older proposals; original attestation signatures and credential/model bindings are rechecked on approval. Concurrent submissions cannot duplicate a mutation or invitation secret. The implemented actions are ordinary invitation, factor testing, factor registration authorized by an existing key, and retiring a factor using a different key. Invitation requires two tested, enabled factors. Two records/public keys still do not prove two physical authenticators.

This is a server-side transport binding, not qualification of a browser/native companion. No cookie-only fallback, general elevated session, public dashboard or administrator self-renewal route exists. Administrator replacement after device loss is still a trusted local owner ceremony, not a password/reset endpoint. Q02/Q03 remain open for actual hostname, browser/OS isolation and two physical devices.

## Recovery boundary

Use age v1.3.2 with an offline X25519 recipient. Export takes a consistent SQLite snapshot, closes requested sessions, revokes all copied enrollments and ordinary certificates, disables administrator devices/factors, clears challenges and marks quarantine. Only public trust/factor and controller domain data are included. Issuer signing-key and offline root recovery are separate; device private keys are never included.

Export returns an independent recovery anchor containing the exact ciphertext SHA-256 and snapshot audit checkpoint. Keep it through a trusted channel separately from the archive. Recipient encryption alone cannot authenticate a sender: anyone with the public recipient can encrypt a forged file. Restore authenticates the complete age stream, verifies the anchor against the same bytes read, checks bounded size/schema/database integrity/audit history, and only then publishes a new quarantined file without overwriting an existing path. Re-encrypting identical plaintext still requires a new trusted anchor. An anchor proves the archived state, not current revocation freshness.

Export/restore are trusted local primitives. Remote backup-export approval, local owner authentication, an independent recovery journal, platform ACL/key-provider qualification and the physical restore/finalization drill remain unimplemented. No unquarantine method exists. Temporary plaintext is owner-directory protected and removed on normal/error completion; an interrupted export/restore may leave a staging file requiring local cleanup. Windows ACLs and host-owner identity cannot be inferred from POSIX mode bits.

## Dependency review and operational limits

Smallstep certificates and go-jose use Apache-2.0; age and go-webauthn use BSD-style three-clause licenses in their pinned source distributions. Project licensing remains Q13; this is not a distribution-license determination. Existing mature maintainers and recent pinned upstream releases were reviewed, with Go checksum verification and SBOM generation. The CA has a much larger dependency graph than the adapter and stays isolated in its own module. Its inherited gRPC, OpenTelemetry, pgx, JOSE v3 and x/crypto versions required security updates; the CI package scan covers imported issuer packages, including optional implementations, without suppressions. Changes in that module must rerun actual issuance and bypass tests.

Q08's adapter and restricted-endpoint mechanism now have executable lab coverage. Production network isolation, issuer custody, management identity rotation, supported OS key storage, independent security review and physical admin/recovery gates remain required. No resource forwarding, routes, DNS, firewall rules, Mullvad settings or global trust stores are changed.

## Primary sources

- [Smallstep certificates v0.30.2](https://github.com/smallstep/certificates/releases/tag/v0.30.2) and [JWK CSR fingerprint validation](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/jwk.go).
- [Smallstep configuration](https://smallstep.com/docs/step-ca/configuration/) and [embedded authority](https://github.com/smallstep/certificates/blob/v0.30.2/authority/authority.go).
- [go-webauthn v0.18.0](https://github.com/go-webauthn/webauthn/tree/v0.18.0) and [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/).
- [age v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2) and [go-jose v4.1.5](https://github.com/go-jose/go-jose/releases/tag/v4.1.5).
