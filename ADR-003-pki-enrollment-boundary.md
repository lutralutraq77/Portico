# ADR-003: PKI validation and durable enrollment boundary

Status: accepted for the Phase 3 component foundation. Q02, Q03 and production Q08 remain open. This decision does not enable a CA, administrator API or deployment.

## Problem and prior implementations

An X.509 signature proves neither current Portico authority nor permission to create an administrator. A CA call and a SQLite transaction cannot commit atomically. Retrying an ambiguous signing request can issue multiple certificates from one invitation.

Go's [crypto/x509](https://pkg.go.dev/crypto/x509) supplies certificate/CSR parsing, signature checking and chain verification. [crypto/tls](https://pkg.go.dev/crypto/tls) supplies possession proof through TLS; VerifyConnection is used for the live registry check. We use these implementations, with an application profile above them, and introduce no cryptographic primitive or encryption protocol. Local review of Go 1.27.1 also found that its CSR parser deliberately omits some attributes, so the Portico wrapper rejects raw attributes as well as parsed claims.

Smallstep's [configuration](https://smallstep.com/docs/step-ca/configuration/) supports disabling renewal. Its [template model](https://smallstep.com/docs/step-ca/templates/) and [renewal behavior](https://smallstep.com/docs/step-ca/renewal/) still require an independently constrained registration-authority integration. Configuration flags alone do not demonstrate that all direct provisioner, renewal and signing paths are inaccessible to clients. step-ca remains the preferred production issuer; no replacement CA implementation is introduced here.

## Decision

Implement the independently testable parts now: strict public-certificate validation, durable enrollment reservations, constrained issuer-result validation, TLS possession proof, live registry checks, ordinary same-key renewal and revocation. Keep the issuer provider as a trusted in-process integration boundary. Only tests implement a signer, using fresh ephemeral keys and crypto/x509. The version-only executable cannot create invitations, sign certificates or start a listener.

Only device and connector profiles are admitted. Administrator/infrastructure profiles fail closed. An ordinary device certificate has clientAuth; a connector certificate has exactly clientAuth and serverAuth. The leaf has an empty subject, P-256 public key, ECDSA/SHA-256 signature, digitalSignature only, CA false, and one critical URI SAN: `portico://<deployment-uuid>/<profile>/<principal-uuid>`. This URI is an identity label, not a dialable address or a claim of SPIFFE conformance. Root and issuer certificates are explicitly pinned; one store cannot mix deployments. Online intermediates require path length zero. A current chain still needs active issuer, user/device or connector, registered leaf, and activated enrollment records.

CSRs are bounded DER and must contain a P-256 proof of possession with no subject, attributes or extensions. IDs, profiles and deadlines come from server-approved records. Issuer output is independently checked against the pinned chain, exact public key and exact approved start/end times. Unrecognized extensions and hidden extra SAN forms reject. Future issuer compatibility changes require explicit profile review.

SQLite schema version 2 adds public trust bindings and enrollment records. Version 1 migrates atomically only after its known digest, integrity, foreign keys and audit history validate; quarantined snapshots cannot migrate into an active controller. The original schema remains embedded so its digest can be checked. No schema downgrade is supported.

Invitations contain 256 random bits and persist only a SHA-256 verifier. The local Invite method returns plaintext only after state and audit commit. Ten-minute invitations are the normal fixture; the enforced maximum is one hour. An invitation binds permanently to one attempt and SPKI. The reserved-to-issuing transition commits before the provider runs. Only that transition may call the provider, once. Errors, cancellation and process death leave uncertain issuance bound; they never restore anonymous reuse. A trusted operator can reconcile the same valid public result or revoke the attempt and start a newly approved invitation. Reconciliation cannot activate a certificate.

Activation requires a completed real TLS 1.3 connection with the matching private key, and rechecks authority in its transaction. Enrollment-only TLS admits registered pending leaves solely for activation; ordinary authentication admits activated leaves. TLS session tickets are disabled. Authenticate rechecks live state after the handshake and at subsequent authorization boundaries. Names and headers do not participate in identity. Read-only checks reject clock times preceding the latest durable audit event; a qualified clock-health system is still required.

Ordinary renewal requires an active TLS identity and same-key CSR, and stays within the existing device and issuer deadlines. A single outstanding renewal is allowed per old credential. Activating the renewal revokes the old certificate atomically and closes requested ledger sessions. Source revocation/expiry before activation invalidates the renewal. This foundation does not support key replacement, implicit certificate overlap or administrator renewal.

## Remaining gates and limits

- Q08: implement and qualify the real step-ca adapter with direct endpoint/provisioner/renewal bypass attempts, isolation and issuer-result reconciliation. No production provider is installed until this passes.
- Q02: select the stable private WebAuthn origin and demonstrate server-verifiable native device binding, including hostile origins and other local users. No browser or cookie fallback exists.
- Q03: qualify actual independent primary/recovery UV-capable hardware keys and their attestation trust procedure. No boolean or virtual authenticator substitutes for this evidence.
- Q06: qualify local owner authentication, encrypted recovery, a restore drill and bootstrap finalization. Snapshots remain quarantined and revoke all copied enrollments.
- Actual OS key providers, administrator authority, fresh WebAuthn approval, key replacement/overlap, encrypted backups and bootstrap ceremonies are not implemented. Test software keys do not establish hardware/platform support.
- No network service or data plane exists. Revocation prevents subsequent authentication and closes requested ledger records; measured closure of forwarding streams remains Phase 5. Admission callbacks alone cannot enforce resource authorization, rate limits or stream cancellation.

The full acceptance cases remain planned where they require the real issuer, admin APIs, platforms, browser, forwarding or recovery ceremony. Component tests are evidence for this boundary, not a waiver of those cases.
