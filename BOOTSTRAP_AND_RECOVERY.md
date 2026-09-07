# Bootstrap and recovery

Status: Phase 0. Q02 (browser/device binding), Q03 (hardware attestation) and Q06 (physical presence) are release gates.

## Staged bootstrap
A clean installation has no public listener or remote recovery endpoint. OS-protected local console/socket authentication unlocks setup. A loopback UI additionally needs a protected bootstrap session, strict Host/Origin checks and CSRF defenses; localhost alone does not authenticate an owner.

| State | Evidence required to advance |
|---|---|
| UNINITIALIZED | Local host-owner authentication; deployment ID; storage/clock checks |
| OWNER_PENDING | Owner display identity and one-time admin enrollment scoped to a device attempt |
| ADMIN_ENROLLED | Private key generated on device; CSR enrollment and fresh mTLS proof succeed |
| ADMIN_ACCESS_VERIFIED | Actual intended private management path and server-side device binding work after reconnect |
| FACTORS_VERIFIED | Primary and distinct recovery hardware keys registered and each tested with user verification |
| RECOVERY_VERIFIED | Independent local recovery ceremony exercised; encrypted offline backup restore-tested in isolation |
| READY_TO_FINALIZE | Evidence remains current; access/recovery preview and fresh hardware approval |
| LOCKED_DOWN | Atomic transition invalidates bootstrap tokens/sessions and closes bootstrap endpoints; regular admin still works |

State is durable; crash must not reopen anonymous bootstrap. Finalization is idempotent with no “skip failed checks” flag. Changing origin, admin device, trust root or management path invalidates the relevant proof. A localhost health check is not proof that the actual administration path works. Incomplete setup is visibly not production-secure.

## Stable browser origin and device factor
WebAuthn origin/RP scope must survive bootstrap. Do not register keys at a temporary origin and assume they work after switching hostnames.

Proposed approach: a native admin companion owns the local device key provider and establishes authenticated management transport; a tightly scoped browser bridge provides the dashboard at a stable secure origin. The server binds each browser session to the verified device identity. The bridge is neither a general signer nor a forwarding proxy.

Evaluate managed browser client certificates and a native admin shell as alternatives. Browser certificate stores, private HTTPS trust, IP-only deployments, stable RP ID, key-provider access, malicious origins, port hijacking and other OS users remain explicit Q02 work. **No cookie-only fallback.** This gate must close before admin PKI integration/dashboard implementation.

## Fresh sensitive-action approval
The server stores an immutable proposed operation containing method, target, changes, resource revision, admin device ID and expiry. A fresh WebAuthn challenge references it. Successful assertion is consumed atomically with a final policy/version recheck, applying exactly that operation. No generic “elevated admin” bearer token.

Use a reviewed WebAuthn server library to verify RP/origin, challenge, credential ownership, signature and required user presence/verification. Never accept a JavaScript “verified” flag. Counter and credential backup state are inputs to authenticator policy, not complete clone detection. [WebAuthn specification](https://www.w3.org/TR/webauthn-3/).

The production profile requires hardware keys supporting user verification; no silent touch-only fallback. Two credential IDs do not prove two physical authenticators. Test two independently held devices. Attachment hints alone do not prove hardware backing. Synced/platform credentials cannot automatically satisfy the independent hardware-factor requirement. Q03 selects attestation trust, supported authenticators and offline metadata maintenance.

Fresh approval covers invitations and secret delivery, admin creation/replacement/renewal, permission increases/extensions, factor enrollment/removal, CA/security/recovery changes, release trust changes and backup export. Emergency denial/termination follows the faster containment rule in the session design.

## Recovery routes
| Failure | Route |
|---|---|
| Primary hardware key lost; admin device valid | Tested backup key, revoke lost factor, register replacement |
| Admin device/key lost | Another valid admin approves new device, or physical console; never download old key |
| Renewal missed/failed | Another valid admin device or console; never accept expired admin certificate indefinitely |
| Both factors lost | Physical-console maintenance ceremony, no public reset |
| Issuer compromised | Quarantine, revoke issuer trust, offline-root ceremony and clean re-enrollment |
| Controller root compromised | Isolate, rebuild clean host, review policy and rotate affected trust |
| Storage loss/stale backup | Quarantined restore, safe authority reconciliation |
| All recovery/trust lost | New installation and re-enrollment |

## Physical recovery ceremony
Future procedure, not an installer:
1. Obtain local console and authenticate as host owner; explicitly enter maintenance, quarantine remote traffic and stop issuance.
2. Record reason and verify deployment fingerprint against recovery media.
3. Distinguish key loss from compromise or rollback. Compromise requires a clean environment.
4. Enroll a new admin key generated on its device; revoke affected old credentials and pending invitations.
5. Register/test primary and backup hardware keys, verify actual remote administration and test encrypted offline backup restoration.
6. Audit, rotate affected trust and leave maintenance only after health/access checks.

Host root, including an attacker with a remote root shell, can generally perform recovery. Software cannot honestly equate every root shell with physical presence. Q06 selects deployment-specific local interactive console plus independent recovery material or equivalent. There is no recovery HTTP API and no claim to defeat root.

## Backup and anti-rollback
Use an established authenticated-encryption format/tool such as age after dependency review; do not invent backup encryption. Offline decryption keys are stored separately.

Back up consistent policy/certificate metadata, WebAuthn public records, issuer configuration, audit sequence, schema/version and public trust state. Online issuer secret export uses the issuer's supported encrypted recovery process. Root backups are separate. Exclude device private keys, live leases, browser sessions, challenges and plaintext invitations.

Restore in quarantine. Clear sessions/challenges/invitations. Reconcile independent current audit/revocation evidence. If freshness cannot be proved, disable restored device/admin/connector credentials and re-enroll before traffic. Merely increasing a database epoch does not invalidate still-trusted old credentials. Release security floors cannot be restored from an untrusted stale archive.

Show backup age, last successful restore test and which material is recoverable. Loss of offline decryption keys may be irrecoverable. Test this operational dependency.

## Audit failure and proof
Recovery cannot silently grant authority if required storage fails. Use an independently protected local recovery journal and restore storage integrity before grants. Emergency stopping/quarantining services remains possible even when logging fails.

BOOT-01–05, REC-01–06 and ADMIN-01–08 are required. A successful wizard alone is not recovery evidence.
