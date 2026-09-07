# enrollment

The canonical design is [PKI_DESIGN.md](../PKI_DESIGN.md).

Durable ordinary enrollment includes hashed invitations, attempt/CSR binding, one issuer invocation, registered public results and real TLS activation. The [restricted issuer](issuer.md) now implements the provider against Smallstep. Administrator-approved ordinary invitations can commit with their one-use WebAuthn assertion and audit event. Administrator bootstrap certificates still enter through a trusted local owner operation; no public registration/reset endpoint exists. See [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) and [current integration evidence](phase-3-integration-report.md).
