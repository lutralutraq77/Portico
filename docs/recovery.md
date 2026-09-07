# recovery

The canonical design is [BOOTSTRAP_AND_RECOVERY.md](../BOOTSTRAP_AND_RECOVERY.md).

Current implementation uses age X25519 recipient encryption for consistent quarantined snapshots. Export returns a trusted local `RecoveryAnchor` containing the exact ciphertext SHA-256 and audit checkpoint; retain it independently from the archive. `RestoreRecovery` requires that anchor and the offline identity, authenticates the entire bounded stream and publishes a new quarantined database only after integrity checks. It never enables restored credentials or overwrites an existing destination.

Export/restore are trusted local primitives, with no recovery HTTP API or unquarantine operation. Windows ACLs, local owner authentication, issuer/root-key custody, fresh hardware approval for remote export and the physical recovery drill remain gates. Temporary plaintext may survive process termination and requires owner-only directory protection and cleanup. See [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) and [current integration evidence](phase-3-integration-report.md).
