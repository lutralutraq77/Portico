# PKI and enrollment design

Status: Phase 0 proposal. No CA or credentials have been created.

## Architecture
Use an offline root and restricted online issuing service. Smallstep documents offline root custody and controlled intermediate operation; current documentation also describes limited CRL support. Live Portico authorization checks remain necessary regardless of CA revocation features. [Production guidance](https://smallstep.com/docs/step-ca/certificate-authority-server-production/) · [Revocation](https://smallstep.com/docs/step-ca/revocation/).

Prefer self-hosted step-ca behind a Portico registration authority. Its inspected [renewal handler](https://github.com/smallstep/certificates/blob/bb481fbf670c24721d5bdb1489ad0d1052c203b5/api/renew.go) has certificate- and token-based entry paths; these do not supply Portico hardware-key approval. Q08 must prove that direct signing/provisioner/renewal access cannot bypass the registration authority. Otherwise reconsider the integration.

Recommend separate intermediates for devices, administrative devices and infrastructure, with distinct issuance credentials and process boundaries where practical. Shared root trust never conveys a role.

## Certificate profiles
Use reviewed X.509/CSR libraries. Recommend ECDSA P-256/SHA-256 leaf keys for initial OS key-store interoperability; verify actual hardware support. TLS key exchange is separately negotiated by the mature library.

| Profile | Identity / permitted usage |
|---|---|
| Device | Typed URI SAN containing deployment UUID and immutable device UUID; clientAuth; CA false; digitalSignature |
| Administrator device | Distinct typed profile and issuer allowlist; clientAuth; live AdminAuthority separately required |
| Connector | Typed immutable connector ID; serverAuth/clientAuth for its endpoint roles; live registry and HostBindings |
| Infrastructure service | Exact expected service ID; narrowly appropriate EKUs and peer/method allowlists |
| Intermediate | CA true, path length zero, keyCertSign/cRLSign as needed; finite lifetime and explicit active issuer record |
| Root | Offline trust anchor; never mounted into a running controller |

CA-generated serials must be unpredictable and unique per issuer. Store issuer+serial, leaf fingerprint and SPKI hash. Reject wrong EKU, CA leaves, unsupported keys, unknown critical extensions, unexpected SANs, foreign deployment and ambiguous profiles. Runtime checks validate both chain and registered active status. CN, names and URI name constraints alone do not enforce application roles.

Use Portico-specific trust bundles; do not automatically install the root into global browser/OS HTTPS trust. Dashboard browser trust is Q02.

## Local key generation
Devices generate private keys locally using Android Keystore, Windows CNG/TPM where supported, or a protected Linux key provider. Only public CSR and certificate metadata reach Portico. Hardware backing must be proven or labeled unavailable; software keys require OS access controls. Non-exportable keys do not prevent malware invoking them.

The CSR proves possession but cannot assign identity, role, SAN or expiry. The issuer derives those fields from the approved enrollment. Reject conflicting/extra identity claims, never copy arbitrary CSR extensions.

## Enrollment state machine
1. Current admin device and fresh operation-bound hardware approval authorize invitation creation.
2. Generate at least 256 random bits using OS CSPRNG. Store only a standard hash/keyed verifier, scope, target, permitted profile/lifetime and expiry. Compare using constant-time library support. High-entropy tokens are not human passwords.
3. Deliver once in the final approved no-store response. Proposed expiry 10 minutes, configurable maximum 1 hour. No secret in lists, initial HTML, URLs or logs.
4. Invitation bundle includes deployment identity and root fingerprint obtained through a trusted channel. The client authenticates the server before sending the token/CSR. No silent trust-on-first-use.
5. Device generates its private key and CSR. Server validates scope, expiry and CSR proof.
6. Atomically reserve invitation to one CSR SPKI and attempt ID. Parallel redemption with another key fails. Identical authenticated retries may retrieve the same public certificate.
7. Issuer signs only the approved profile/ID/lifetime. Register the credential and consume invitation durably with audit. Signed-but-unregistered certificates cannot authenticate.
8. Device proves the new credential on a fresh connection before being marked operational.

Signing and controller database writes are not one transaction. Use durable reserved/issuing/issued/activated/failed states and reconciliation. A crash never returns a bound reservation to anonymous reuse. Quarantine uncertain issued serials; failures require expiry/revocation and a new invitation, not unlimited issuance.

A stolen bearer invitation can win the first redemption. Admin enrollment additionally requires the local ceremony or existing admin approval of the new public-key fingerprint. An ordinary invitation cannot create admin authority. Optional ordinary-device fingerprint confirmation is a later assurance option.

## Reveal and secret handling
A hashed invitation cannot be redisplayed. Lost delivery requires revocation and a newly approved invitation. Masked APIs contain metadata only. Do not store retrievable plaintext just to provide a reveal button.

Device private keys are absent from controller backups, logs, browser storage and images. Disable TLS key logging in production. Strip request bodies, authorization headers and secret values from tracing, crash diagnostics and metrics.

## Renewal and replacement
Ordinary renewal requires a current key, active credential and remaining device enrollment authority; it extends neither authority nor grants. Admin renewal additionally requires fresh independent hardware approval enforced through the issuer integration. Every certificate and authority deadline remains separate.

Planned key rotation has a bounded explicit overlap. Compromise/loss replacement revokes the selected old credentials and cancels their sessions. Expiry alone is insufficient for immediate revocation; CRLs do not close an already-established stream. [Session design](SESSION_AND_REVOCATION_DESIGN.md) owns those rules.

## CA recovery
Issuer compromise: quarantine issuance, mark issuer inactive in live verification, cancel affected sessions, use offline root to establish a clean intermediate, then reissue after validating controller/registration authority.

Root compromise: establish a new root out of band and re-enroll. An update authenticated only by the compromised root does not repair trust. Loss without compromise may use a tested encrypted offline root backup. Total loss of trust/recovery copies requires rebuild and re-enrollment.

Normal rotation stages new public trust, verifies components, overlaps narrowly and retires old issuer. Offline devices that miss trust retirement must recover through trusted enrollment; never retain obsolete roots indefinitely.

AUTH-01–08, PKI-01–06, ADMIN-01–06 and REC-03 are required. CTRL-01/04/05/06 record trust, failure and recovery.
