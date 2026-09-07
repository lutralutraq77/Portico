# Restricted issuer development service

The implementation and security limits are in [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md). This is an isolated development service, not a deployed CA or a supported production installer.

`issuer/` is a separate Go module, pinned to Smallstep certificates v0.30.2 with reviewed transitive security updates. `scripts/check.ps1` verifies both modules, runs real issuance and process tests, scans imported issuer packages and builds Windows/Linux binaries. The main Portico CLI still has no network endpoint.

~~~powershell
./build/portico-issuer-windows-amd64.exe version
./build/portico-issuer-windows-amd64.exe serve --config E:\Portico\work\private-lab\issuer.json
~~~

The second command requires owner-created configuration and keys. No production configuration or keys are supplied, and no key generation or trust-store modification is performed by the command. The configuration is strict JSON with these fields; every file/database path must be absolute, local and inside an owner-protected directory:

| Fields | Meaning |
|---|---|
| ListenAddress, Endpoint | Explicit loopback IP/port and matching https://localhost:port endpoint; no public/private LAN listener permitted by the command yet |
| DeploymentID, IssuerID, Profile | Canonical deployment/issuer UUIDs and one fixed device, connector or administrator profile |
| Provisioner, KeyID, ProvisionerPublicKeyFile | Sole JWK provisioner name, key ID and ES256 **public** JWK file; its private key stays with the controller |
| RootCertificateFile, IssuerCertificateFile | Exactly one PEM public root and constrained intermediate certificate each |
| IssuerKeyFile, IssuerPasswordFile | Encrypted PKCS#8 intermediate key and separate owner-protected noninteractive password file; never the offline root key |
| ServerCertificateFile, ServerKeyFile | Separate localhost management server TLS certificate/key |
| ControllerRootFile, ControllerSPKI | Management client root and SHA-256 of the exact permitted controller client SPKI |
| DatabasePath | Dedicated local bbolt database for replay protection, immutable issuer binding and public receipts |

Do not place live passwords, signing keys or real configuration in Git. Parent directory ownership/ACLs, password-file custody and clean-host assumptions are operational prerequisites, not checks performed by a mode-bit setting. The fixture password file is separate from the encrypted key; encryption does not protect against an attacker who reads both.

Stop the issuer before an offline lookup with `portico-issuer result --config ABSOLUTE_PATH --attempt UUID`. It prints only the verified public certificate. The controller must reconcile it against the original reserved attempt and CSR before activating it with actual TLS possession proof. A missing receipt is an unresolved outcome, never permission to retry signing. Receipt lookup does not export the signing key or restart a listener.

Tests generate ephemeral keys and one-use encrypted configuration in their test directories. They cover actual step-ca signing over mutual TLS, a separate issuer process, profile constraints, CSR binding, unknown fields, direct endpoint bypass, missing/wrong/unpinned controller keys, replay across restart and local receipt recovery. Linux VM tests use guest loopback only, no NIC or host filesystem shares.
