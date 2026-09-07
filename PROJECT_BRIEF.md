# Portico project brief

Status: Phase 0 design proposal · 7 September 2026 · No implementation or production assurance.

## Purpose and scope
Portico is a self-hosted private-access system with this authorization chain:

**Identity → Policy → Resource → Connector → Destination**

The owner defines a named service, assigns particular enrolled devices, and can revoke or expire access. Ordinary users need neither passwords nor email. Each device generates its own private key. Sensitive administration additionally requires an independent FIDO2 hardware key.

The first useful MVP includes a controller, Docker Compose deployment, Linux connector, Linux/Arch and Windows clients, an Android client, certificate enrollment, resource grants, audit, recovery, and a Material Design 3 dashboard. Windows connector follows immediately if necessary; Android connector is optional. Android client is never an optional substitute for “MVP.”

This package implements the brief's **First Task only**: research and design. Phase 1 and all application code, networking, installation, CI setup, and deployment await explicit authorization.

## Product example and security boundary
Alice's Pixel receives a device grant for Jellyfin at `192.168.50.10:8096/TCP` through Home Server. The connector opens that exact socket only after authorization. SSH, neighboring ports, router management, subnets, other devices, and Internet forwarding receive no grant.

An authorized TCP service can itself be a proxy, SSH tunnel, shell, vulnerable application, or router. Portico cannot prevent application-mediated pivots merely by checking a port. Destination-side egress isolation and application authentication are required. “No lateral movement” is a required Portico enforcement property, not a claim that a compromised application or root host becomes harmless.

## Non-goals for the initial product
No full mesh, CIDR resources, wildcard destinations, port ranges, exit node, default-route takeover, transparent general Internet proxy, global DNS replacement, user-key escrow, hosted identity dependency, or automatic router configuration. UDP resources and integrated SSH certificates are later work. Public ingress is an explicit deployment choice; development is private and isolated.

## Success measures
- One explicit device/resource grant permits exactly one reviewed destination tuple.
- Device names and usernames cannot affect cryptographic identity.
- A stolen administrator certificate alone cannot create authority, display invitations, or renew administrator authority.
- Revocation blocks new authorization at the authoritative commit and terminates existing streams within documented bounds.
- Bootstrap cannot finalize without verified administration, two tested hardware keys, and tested console recovery.
- LAN, Docker and IPv6 isolation and server Mullvad coexistence are demonstrated in the supported deployment profile.
- Every critical mechanism has an owner, failure behavior, recovery path, and acceptance test.

These are requirements. None has yet been demonstrated by running Portico software.

## Documentation authority
[Security invariants](SECURITY_INVARIANTS.md) constrain all designs. [Session design](SESSION_AND_REVOCATION_DESIGN.md) owns timing. [Resource model](RESOURCE_MODEL.md) owns policy semantics. [PKI](PKI_DESIGN.md) owns certificate profiles. [Protocol design](PROTOCOL_DESIGN.md) owns proposed wire boundaries. [Open questions](OPEN_QUESTIONS.md) owns unresolved decisions. [Acceptance plan](ACCEPTANCE_TEST_PLAN.md) distinguishes planned tests from evidence.

Proposed defaults are reviewable engineering choices, not settled standards or implementation facts. Sources are recorded in [the research register](RESEARCH_SOURCES.md); Portico adaptations are identified as proposals.

## Operating constraints
All deliverables and scratch work for this task reside on E:. No changes to the real router, firewall, Mullvad, DNS, production server, routes, or public services. No remote repository is created or publication performed. No production secrets are generated. Source snapshots used for research remain in separate scratch storage.
