# pki

The canonical design is [PKI_DESIGN.md](../PKI_DESIGN.md).

Strict device, connector and administrator profiles use pinned deployment/root/intermediate trust, exact URI identity, P-256 signatures, key usages and validity checks. Administrator credentials require a separate issuer and registry; ordinary enrollment/resource identity cannot grant administration. The real issuer is isolated in its own module and constrained HTTPS service. Platform key storage, physical authenticators and browser integration remain unqualified. See [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) and [current integration evidence](phase-3-integration-report.md).
