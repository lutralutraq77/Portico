# PORTICO — MASTER DESIGN AND IMPLEMENTATION PROMPT

You are the lead security architect and senior engineer for a new open-source project currently named:

PORTICO

Portico is a self-hosted, resource-oriented private-access system inspired by the useful architectural concepts of Twingate, NetBird, OpenZiti, Teleport, Smallstep and similar mature systems.

It is NOT intended to be a conventional full-mesh VPN.

The core mental model is:

    Identity -> Policy -> Resource -> Connector -> Destination

A user should receive access ONLY to explicitly authorized resources, not to the server, subnet, LAN or connector generally.

Portico is intended eventually to be published publicly on GitHub.

Security, maintainability, auditability, portability and recoverability take priority over development speed.

Do not "vibe code" the security architecture.

Do not implement custom cryptographic primitives.

Do not invent a new encryption protocol.

Use mature, reviewed cryptographic libraries and established protocols wherever possible.

Before making a major architectural decision, investigate how mature open-source projects solve the same problem and document the reasoning.

======================================================================
0. OPERATING RULES FOR CODEX
======================================================================

Work incrementally.

Before substantial implementation, create and maintain:

- architecture documentation
- threat model
- security invariants
- trust-boundary documentation
- protocol documentation
- certificate lifecycle documentation
- recovery design
- acceptance tests
- compatibility requirements
- update/security-release design

Security-critical behavior MUST be testable.

If a requested feature conflicts with a security invariant, stop and document the conflict rather than silently weakening security.

Do not configure the developer's real routers, firewall, Mullvad installation, production server networking or public DNS.

Development and testing must initially work in isolated development environments.

Do not assume the development machine is the production system.

Do not expose experimental Portico services publicly during development.

Keep production deployment separate from development.

The repository must remain buildable and understandable by someone other than the original developer.

Prefer boring, established technology to clever custom security mechanisms.

======================================================================
1. PRODUCT GOAL
======================================================================

Build a secure, self-hosted private-access platform in which an administrator can:

1. Install one or more Portico Connectors near private services.

2. Define resources through a simple dashboard.

3. Assign those resources to specific users/devices.

4. Enroll devices using certificate-backed identities.

5. Allow an authorized client to reach ONLY the resources assigned to it.

6. Revoke access immediately or allow it to expire automatically.

7. Manage everything without requiring a cloud-hosted identity provider,
   email address, SaaS account or third-party authentication service.

A resource should feel approximately as simple to configure as a
Twingate resource.

The basic UI should normally ask for:

    Resource name
    Connector
    Destination address/IP
    Port

Protocol should default sensibly, normally TCP, while allowing an
advanced selection when necessary.

A possible example is:

    Name: Jellyfin
    Connector: Home Server
    Destination: 192.168.50.10
    Port: 8096
    Protocol: TCP

Granting this resource MUST NOT grant:

    192.168.50.10:any-other-port

or:

    192.168.50.0/24

or:

    access to the LAN

or:

    access to the connector host itself.

======================================================================
2. SECURITY PHILOSOPHY — ASSUME MALICIOUS INTENT
======================================================================

Portico must follow a hostile-by-default security model.

Assume that any:

- user
- non-admin client
- client machine
- connector
- resource
- application
- network
- LAN device
- packet
- API caller

may eventually become malicious or compromised.

Possession of one permission MUST NOT imply possession of another.

The fundamental rule is:

    Grant exactly what was requested and nothing else.

If Alice is authorized for:

    Jellyfin -> server.example.internal:8096

Alice must not thereby be able to reach:

    SSH
    Docker APIs
    Portainer
    databases
    dashboards
    other containers
    other server ports
    other LAN hosts
    the router
    the Portico controller
    management APIs

Authorization must be based on explicit positive grants.

No implicit full-LAN access.

No implicit subnet routing.

No default full mesh.

No automatic gateway functionality.

No exit-node behavior.

No "allow all ports on this host" as a hidden side effect.

Lateral movement through Portico must be considered a critical security failure.

Where possible, connectors should proxy or relay explicitly authorized
resource connections rather than handing clients unrestricted layer-3
access to private networks.

A vulnerability in Jellyfin may compromise Jellyfin or its container.
The Portico architecture should make it substantially harder for that
compromise to become unrestricted Portico or LAN access.

Document where Portico's responsibility ends.

Application-layer authentication remains required.

For example, allowing TCP/22 permits connection to SSH but does not replace
SSH authentication.

Allowing Jellyfin does not bypass Jellyfin accounts and permissions.

======================================================================
3. ARCHITECTURAL COMPONENTS
======================================================================

Design Portico as separate components with narrow privileges.

At minimum:

PORTICO CONTROLLER

Responsible for:

- identities
- devices
- connectors
- resources
- authorization policies
- certificate metadata
- enrollment state
- revocation
- session authorization
- audit events
- compatibility/version information

PORTICO DASHBOARD

Administrator interface.

Must NOT be publicly exposed by default.

Prefer access from:

- local machine during bootstrap
- Portico administrative resource after bootstrap

PORTICO CONNECTOR

Lives close to protected resources.

Receives permission to provide only explicitly configured resources.

It should not automatically advertise or expose an entire network.

PORTICO CLIENT

Runs on authorized user devices.

Establishes authenticated access into Portico.

It receives access only to assigned resources.

PORTICO PKI / CERTIFICATE SERVICE

Handles certificate issuance and lifecycle.

Separate root and issuing responsibilities appropriately.

PORTICO POLICY ENGINE

Authoritatively determines:

    WHO
    using WHICH DEVICE
    can ACCESS
    WHICH RESOURCE
    through WHICH CONNECTOR
    and UNTIL WHEN.

PORTICO AUDIT SYSTEM

Records security-relevant actions without recording secrets.

Consider separating the management plane and data plane so compromise
of one component does not automatically mean unrestricted control of the other.

======================================================================
4. CLIENT AND CONNECTOR PLATFORMS
======================================================================

Required CLIENT platforms:

- Arch Linux
- generic modern Linux
- Windows
- Android

Required CONNECTOR platforms:

- Docker / Docker Compose
- Linux / Ubuntu Server
- Windows

Optional / experimental connector:

- Android

Android connector functionality is NOT required for MVP.

Android CLIENT functionality IS required.

The architecture must not assume one Linux distribution.

Platform-specific software may differ internally, but security semantics
must remain equivalent.

A Windows client must not receive weaker identity or policy enforcement
than a Linux client.

======================================================================
5. DOCKER REQUIREMENTS
======================================================================

The controller and connector architecture should be Docker-friendly.

Provide a supported Docker Compose deployment.

However:

DOCKER MUST NOT BYPASS PORTICO'S SECURITY MODEL.

Explicitly account for:

- Docker-published ports
- Docker NAT
- iptables/nftables interaction
- host networking
- bridge networks
- IPv6
- containers listening on 0.0.0.0
- containers accidentally exposed to the LAN

Do not depend solely on simplistic host INPUT firewall rules if Docker
can bypass those rules.

Include tests demonstrating that normal LAN clients cannot reach protected
Docker applications directly.

Secrets and identity material must not be baked into container images.

Persistent configuration, secrets and binaries/images must have clear
separation.

======================================================================
6. RESOURCE MODEL
======================================================================

A Resource is the central authorization primitive.

Internally it should contain at least:

- immutable resource ID
- human-readable name
- connector ID
- destination address
- destination port
- transport protocol
- enabled/disabled state
- authorization bindings
- audit metadata

Optional later fields:

- hostname
- virtual alias
- private DNS name
- tags
- health information
- description
- application type

Keep the ordinary UI simple.

Advanced fields should remain behind an Advanced section where possible.

Avoid CIDR/subnet access in the initial product.

If network-range access is eventually introduced, treat it as a separate,
clearly dangerous feature with stronger warnings and policy controls.

======================================================================
7. CONNECTOR SECURITY MODEL
======================================================================

Connectors are not trusted simply because they are connectors.

A connector should receive explicit permission to HOST/provide particular
resources.

This should conceptually resemble OpenZiti's distinction between permission
to dial a service and permission to bind/host a service.

Clients have permission to access resources.

Connectors have permission to provide resources.

These permissions are independent.

A compromised connector should not automatically become an administrator.

A connector must never receive the ability to create users, grant policies
or alter global security configuration merely because it carries traffic.

======================================================================
8. USER AND DEVICE IDENTITIES
======================================================================

Do not require email addresses.

Do not require normal username/password authentication for ordinary users.

Users may have human-readable usernames, but the username is NOT the
security credential.

Every enrolled device receives its own cryptographic identity.

Device identity must be unique and individually revocable.

The client device generates its private key locally.

PRIVATE USER KEYS MUST NEVER BE GENERATED CENTRALLY AND THEN STORED FOR DOWNLOAD.

The server retains:

- public key / certificate information
- fingerprint
- device identity
- owner/user relationship
- issuance time
- expiry
- revocation information
- authorization metadata

The private key remains on the device.

Changing the username presented by a client MUST NOT change authorization.

The cryptographic device identity determines the principal.

======================================================================
9. NON-ADMINISTRATOR CERTIFICATES
======================================================================

A non-admin user only gains access after an administrator explicitly
authorizes enrollment.

Enrollment should use short-lived, single-use invitation material.

The administrator can specify an authorization/certificate lifetime.

Examples might include:

    2 hours
    1 day
    7 days
    30 days
    custom expiry

The system should have configurable maximum lifetimes.

Expiry, resource authorization expiry and active-session lifetime are
separate concepts and must be represented separately.

Expired or revoked credentials must fail predictably.

Lost credentials are revoked and replaced.

They are NEVER "recovered" from Portico because Portico does not retain the
private key.

Users must not be able to retrieve another user's enrollment material.

======================================================================
10. ADMINISTRATOR AUTHENTICATION
======================================================================

Administrators require stronger authentication.

Base administrator identity:

    administrator device certificate

Sensitive administrative operations additionally require fresh
secondary authentication.

Preferred secondary authentication:

    FIDO2 / WebAuthn hardware security key
    requiring user verification via PIN or biometric where supported.

Support registration of at least two security keys:

    primary key
    recovery key

Do not require email or a cloud account for this authentication model.

Fresh secondary authentication should be required for operations such as:

- creating/replacing administrator identities
- creating credentials/enrollment invitations
- displaying a sensitive enrollment invitation
- increasing permissions
- extending privileged authorization
- changing authentication settings
- changing recovery settings
- creating administrators
- modifying CA/security-critical configuration
- disabling important security protections

Username + certificate is NOT considered two-factor authentication.

======================================================================
11. ADMIN CERTIFICATE LIFECYCLE
======================================================================

Support short-lived administrator authorization.

Do NOT hard-code the product to one rotation schedule.

Implement rotation/lifetime policy generically.

The owner should eventually be able to configure a rule such as:

    Administrator credential expires every day at 12:00 Europe/London.

Timezone and daylight-saving behavior must be explicit.

A renewed administrative credential should require independent hardware-key
approval rather than trusting only the previous certificate.

Critical principle:

    Possession of a stolen current administrator certificate must not be
    sufficient to renew administrative authority indefinitely.

Clearly define:

- certificate expiry
- authorization expiry
- renewal window
- existing-session behavior
- forced session termination
- offline-device behavior
- failure behavior

A failed renewal must fail closed for remote administration while still
leaving an independent physical recovery path.

Do not make certificate rotation the only recovery mechanism.

======================================================================
12. SAFE FIRST BOOT / BOOTSTRAP
======================================================================

One of the highest priorities is preventing the legitimate owner from
accidentally locking themselves out during initial setup.

Implement a staged bootstrap flow.

Initial administration is local-only.

Possible bootstrap methods include:

- local console
- localhost
- protected Unix socket
- equivalent operating-system-local mechanism

The first setup wizard should:

1. Establish the owner identity.

2. Generate a short-lived one-time enrollment token.

3. Enroll an administrator device.

4. Generate the administrator private key on that device.

5. Confirm that remote/admin authentication actually works.

6. Register a FIDO2 security key.

7. Strongly require registration of a recovery key.

8. Establish physical-console recovery.

9. Create encrypted backup/recovery material where appropriate.

10. Test recovery.

11. Only then allow bootstrap mode to be permanently disabled.

The system MUST NOT permanently lock itself down before a working
administrator identity has been demonstrated.

However, bootstrap mode must not silently expose Portico publicly.

While bootstrap is incomplete, the UI should clearly state that setup is
not complete and the installation is not yet considered production-secure.

======================================================================
13. RECOVERY
======================================================================

Physical console access must remain an independent recovery mechanism.

Recovery must not depend on:

- email
- SaaS
- current working Portico tunnel
- a single administrator certificate

Provide documented recovery procedures.

Support:

- backup hardware key
- encrypted offline backup
- CA recovery procedures
- owner recovery
- certificate revocation/replacement

Recovery actions must be audited.

Dangerous recovery actions should be intentionally difficult to perform
remotely.

======================================================================
14. ONE-PUBLIC-PORT DEPLOYMENT
======================================================================

Portico must support deployments in which the home network exposes only a
very small number of infrastructure entry points.

A preferred topology is:

    Internet
       |
    ISP router
       |
    optional secondary router/firewall
       |
    Portico entry gateway
       |
    connectors/resources

A deployment should, where technically practical, be capable of operating
through ONE externally forwarded Portico infrastructure port.

Do not expose:

- Jellyfin
- SSH
- dashboards
- databases
- Docker APIs
- router administration
- individual application ports

directly to the Internet merely because Portico exists.

The one-port capability MUST NOT be hard-coded.

Ports, protocols, addresses, NAT layout and router topology are deployment
configuration.

The architecture should also work with:

- one router
- double NAT
- an optional secondary router such as an AX18
- a dedicated gateway
- a VPS/relay added later
- different ISPs
- different external ports

Do not assume UDP/51820 or any other particular port permanently.

If one-port operation requires multiplexing, QUIC or another transport,
use a mature protocol/library and document the tradeoffs.

Do not invent a new secure transport protocol.

======================================================================
15. ROUTER AND HARDWARE ABSTRACTION
======================================================================

Portico must not be specific to:

- Plusnet
- TP-Link
- Archer AX18
- one server
- one subnet
- one ISP

Those should exist only as deployment examples.

The architecture is:

    external network
       ->
    router/NAT/firewall chain
       ->
    Portico ingress
       ->
    authorized connector
       ->
    authorized resource

The TP-Link AX18 may optionally provide additional segmentation.

Portico security must not depend on its presence.

======================================================================
16. NORMAL LAN ISOLATION
======================================================================

An important deployment mode is:

Normal LAN/Wi-Fi machines MUST NOT directly reach protected server
applications.

This includes:

- SSH
- Jellyfin
- dashboards
- databases
- Docker published ports
- management interfaces

The owner can still recover from the physical server console.

Authorized Portico devices can reach assigned resources.

LAN isolation should cover:

- IPv4
- IPv6
- Docker
- alternate interfaces
- accidental port publication

Firewall changes must be performed using safe deployment practices,
including rollback where appropriate.

======================================================================
17. MULLVAD COEXISTENCE
======================================================================

Portico MUST be designed not to break an existing Mullvad deployment on
the server.

The primary server requirement is non-negotiable.

Portico must not:

- steal the host default route
- become an Internet exit gateway
- leak torrent traffic outside Mullvad
- disable a qBittorrent kill switch
- globally overwrite DNS without explicit configuration

Prefer application-specific Mullvad isolation for software such as
qBittorrent.

Portico resource traffic and Mullvad Internet traffic should operate as
independent routing domains wherever practical.

Create integration tests demonstrating that:

1. qBittorrent remains routed through Mullvad.

2. A Mullvad failure continues to enforce the intended torrent kill switch.

3. Portico resources remain reachable according to policy.

4. Portico cannot accidentally route torrent Internet traffic.

5. Portico does not automatically provide Internet gateway functionality.

Client-side Mullvad coexistence is also desirable, particularly on Arch
Linux.

Do the best technically safe implementation possible on:

- Arch Linux
- Windows
- Android

Document platform limitations instead of hiding them.

======================================================================
18. DNS
======================================================================

Portico must not take ownership of global DNS by default.

Default behavior:

    Do not modify DNS.

Portico resources should be usable using IP/address + port without requiring
Portico DNS.

Optional future/private DNS should use split DNS.

Only explicitly configured private domains/suffixes should be resolved
through Portico DNS.

Do not overwrite:

- Mullvad DNS
- local DNS
- user-defined DNS
- DNS-over-HTTPS configuration

unless the owner explicitly enables a compatible feature.

DNS failure must not destroy the underlying certificate identity or
recovery path.

======================================================================
19. SSH
======================================================================

SSH should simply be usable as another Portico resource.

For example:

    Resource: Home Server SSH
    Address: 10.10.10.5
    Port: 22
    TCP

Only assigned identities can establish a connection to TCP/22.

Portico network authorization does NOT replace SSH authentication.

Also design an OPTIONAL integrated SSH certificate module.

Preferred approach:

- device generates SSH private key locally
- private key remains on device
- Portico stores only the public key
- a trusted SSH CA can issue short-lived SSH user certificates
- certificate issuance follows explicit authorization
- privileged issuance can require hardware-key confirmation

Never build a dashboard that stores everyone's reusable SSH private keys.

This SSH CA functionality can come after the core resource access system.

======================================================================
20. MANAGEMENT UI
======================================================================

Use Google Material Design 3 as the primary UI design reference.

The dashboard must work well on desktop and mobile.

Important pages:

DASHBOARD
- status
- security warnings
- connectors
- active sessions
- expiring credentials
- update status

USERS
- username
- devices
- resources
- authorization expiry
- revoke

DEVICES
- certificate fingerprint
- platform
- enrollment date
- last seen
- expiry
- revoke

RESOURCES
- name
- connector
- address
- port
- protocol
- assigned identities

CONNECTORS
- name
- status
- version
- provided resources
- last seen

ACCESS / POLICIES
- effective permissions

ENROLLMENT
- invitation creation
- expiry
- status
- masked secret handling

SECURITY
- FIDO2 keys
- administrators
- certificate settings
- recovery status

AUDIT
- security events
- actor
- target
- timestamp
- result

UPDATES
- controller version
- connector versions
- client compatibility

BACKUPS / RECOVERY

SETTINGS

======================================================================
21. SECURITY UX
======================================================================

The UI itself is part of the security system.

Before applying an access change, show an EFFECTIVE ACCESS PREVIEW.

Example:

    This change allows:
      Alice / Pixel 9
        ->
      Jellyfin
      192.168.50.10:8096/TCP

    This does NOT allow:
      other ports on 192.168.50.10
      other LAN devices

Make dangerous implications visible.

Security-critical actions should use appropriate Material dialogs.

Require fresh secondary authentication where defined.

Never put secret enrollment material in HTML or API payloads before the
user has completed the required secondary-authentication step.

Masking must be server-enforced, not CSS/JavaScript hiding.

Avoid unsafe convenience buttons such as:

    Give full network access

unless such a feature is explicitly added later with extremely clear
security treatment.

Design against accidental administrator lockout.

Support keyboard navigation.

Meet sensible accessibility standards.

Use sufficiently large mobile touch targets.

======================================================================
22. SECRET HANDLING
======================================================================

Secrets must never be:

- written to normal logs
- returned unnecessarily by APIs
- embedded into JavaScript
- cached in browser storage without strong justification
- committed to Git
- included in container images
- printed into crash reports

Sensitive responses should use defensive cache controls.

Invitation material should be:

- short lived
- single use
- scoped to one action/device
- revocable

APIs must enforce the exact same security policy as the graphical dashboard.

There must be no weaker alternate API path.

======================================================================
23. PKI DESIGN
======================================================================

Use established PKI practices.

Investigate a design involving:

    offline/protected root CA
        ->
    restricted online issuing intermediate
        ->
    device certificates

Do not assume this exact layout without evaluating operational complexity,
but protect long-term signing keys particularly carefully.

Use modern standard algorithms supported reliably across Linux, Windows
and Android.

Certificate identity and policy should use immutable identifiers rather
than mutable usernames.

Design revocation deliberately.

Certificate expiry alone is insufficient for immediate revocation.

Determine how Portico distributes revocation state and terminates or
limits active sessions.

Document offline-controller behavior.

Fail-safe semantics must be explicit.

======================================================================
24. SESSION SECURITY
======================================================================

Define separately:

- device certificate lifetime
- resource authorization lifetime
- session lifetime
- idle timeout
- administrator reauthentication lifetime

Revocation must prevent new connections rapidly.

Provide a mechanism for immediate session termination when the administrator
requests it.

Do not assume that issuing a replacement certificate revokes the old one.

This must be explicitly implemented and tested.

======================================================================
25. UPDATES
======================================================================

Portico must have a secure update model from the beginning.

Publish signed releases.

Do not blindly trust "latest".

Docker deployments should support pinned version tags.

Clients/connectors should verify update authenticity.

Separate:

    update available
    download
    verification
    installation
    restart
    rollback

Do not automatically apply an update that could lock out the owner unless
the owner explicitly enables such behavior.

Maintain backwards/forwards compatibility rules.

The controller should show incompatible versions clearly.

Keep credentials/configuration separate from replaceable binaries.

Consider:

- release signing
- SBOM generation
- dependency scanning
- provenance/build attestations
- reproducible or strongly documented builds

where practical.

======================================================================
26. OPEN-SOURCE SUPPLY CHAIN
======================================================================

Minimize security-critical dependencies.

Pin dependencies appropriately.

Enable automated vulnerability scanning.

Use static analysis.

Use dependency review.

Use secret scanning.

Use code formatting and linting.

Use CI.

Use unit tests.

Use integration tests.

Use security-focused tests.

Document dependency/security upgrade policy.

Avoid importing an enormous framework merely to avoid writing a small
non-security-critical function.

Conversely, DO use mature libraries rather than implementing cryptography,
TLS, WebAuthn, parsing or other dangerous primitives yourself.

======================================================================
27. AUDIT LOGGING
======================================================================

Audit events must include appropriate actions such as:

- login success/failure
- certificate issuance
- enrollment
- revocation
- resource creation
- permission change
- administrator creation
- FIDO2 registration/removal
- recovery event
- session termination
- security-setting change
- software update

Audit logs must NEVER contain:

- private keys
- enrollment secrets
- FIDO2 secrets
- passwords
- bearer tokens

Design logs to be tamper-evident or exportable to an external append-only
destination later.

======================================================================
28. COMPARATIVE ARCHITECTURE VALIDATION
======================================================================

Before finalizing critical subsystems, study mature approaches.

Relevant inspiration includes:

TWINGATE
- resource-centric access model
- connectors
- per-resource access rather than traditional VPN LAN exposure

NETBIRD
- policy management
- peers
- routes
- cross-platform networking experience

OPENZITI
- identity-oriented zero-trust services
- dial versus bind/host permissions
- service-level abstraction

TELEPORT / SMALLSTEP
- short-lived certificates
- certificate lifecycle
- SSH certificate practices
- CA operational models

OWASP
- ASVS
- authentication/session guidance
- secure application design

Also inspect other appropriate mature open-source systems.

Do not blindly clone any one project.

Produce an architecture comparison document showing:

    Proven pattern
    Source project
    Portico adaptation
    Security reason
    Portico-specific deviation
    Required tests

Custom Portico behavior should receive MORE scrutiny than borrowed
well-established patterns.

======================================================================
29. SECURITY QUALITY GATE
======================================================================

Before Portico can be considered production-capable, the following must
exist:

- written threat model
- documented trust boundaries
- security invariants
- certificate lifecycle design
- enrollment design
- revocation design
- session design
- recovery design
- firewall/network assumptions
- dependency/security policy
- acceptance-test suite
- manual security review checklist
- automated security scanning
- update rollback strategy

No critical security control should exist only as an undocumented behavior
in source code.

======================================================================
30. SECURITY ACCEPTANCE TESTS
======================================================================

Create automated tests wherever technically possible.

At minimum prove:

AUTHENTICATION

- Correct username without correct private key cannot authenticate.
- Wrong device key fails.
- Expired certificate fails.
- Revoked certificate fails.
- Copying/changing a username does not change identity.

AUTHORIZATION

- User assigned Jellyfin can reach Jellyfin.
- Same user cannot reach SSH.
- Same user cannot reach another port on Jellyfin's host.
- Same user cannot reach another LAN host.
- Same user cannot use Portico as an Internet gateway.

CONNECTOR

- Connector can provide assigned resources.
- Connector cannot grant itself arbitrary resources.
- Connector compromise does not automatically grant controller admin.

ADMIN

- Sensitive actions require fresh FIDO2 approval.
- Stolen administrator certificate alone cannot indefinitely renew admin
  authority.
- Revoking admin identity prevents subsequent administrative sessions.

SESSION

- Explicit session termination works.
- Credential replacement does not accidentally leave old credential valid.
- Expiry semantics match documentation.

LAN

- LAN host cannot directly reach protected application.
- Docker publication cannot bypass intended isolation.
- IPv6 cannot bypass intended isolation.

MULLVAD

- Torrent workload remains bound to Mullvad.
- Portico does not become a torrent traffic route.
- Mullvad failure retains kill-switch behavior.

DNS

- Default installation does not alter system DNS.
- Split DNS modifies only configured private zones.

RECOVERY

- Lost admin credential can be recovered using documented offline/local
  recovery.
- Failed credential renewal is recoverable.
- Backup/restore preserves the intended identity and policy state.

BOOTSTRAP

- Administrator cannot accidentally finalize setup without a working
  administrator identity.
- Bootstrap interface is not publicly exposed.

======================================================================
31. DOCUMENTATION
======================================================================

Documentation is a product requirement.

Create and maintain:

README.md

docs/architecture.md
docs/threat-model.md
docs/security-model.md
docs/trust-boundaries.md
docs/resource-model.md
docs/pki.md
docs/enrollment.md
docs/revocation.md
docs/sessions.md
docs/recovery.md
docs/networking.md
docs/dns.md
docs/mullvad.md
docs/updates.md
docs/audit.md
docs/api.md
docs/development.md
docs/testing.md

Platform documentation:

docs/install/ubuntu-server.md
docs/install/docker-compose.md
docs/install/arch-linux-client.md
docs/install/linux-client.md
docs/install/windows-client.md
docs/install/windows-connector.md
docs/install/android-client.md

If Android connector is eventually supported:

docs/install/android-connector.md

Also create:

SECURITY.md
CONTRIBUTING.md
CHANGELOG.md

Provide diagrams using text/Mermaid where suitable.

Documentation should explain what Portico DOES NOT protect against.

For example:

A root compromise of the Portico controller cannot be treated as though
dashboard role permissions still provide meaningful secrecy from root.

======================================================================
32. API DESIGN
======================================================================

Build an explicit versioned API.

Dashboard authorization and API authorization must be identical.

Never make the UI the security boundary.

Use strong request validation.

Avoid mass-assignment vulnerabilities.

Use immutable IDs.

Implement CSRF protection where relevant.

Use safe session/cookie policy where relevant.

Use structured error handling that does not leak secrets.

Security-sensitive endpoints should have explicit authorization handlers,
not generic "admin-ish" checks.

Document all security-sensitive API calls.

======================================================================
33. DEVELOPMENT APPROACH
======================================================================

Use a staged implementation.

PHASE 0 — RESEARCH AND DESIGN

Do not implement production networking.

Create:

- project brief
- architecture
- competitor architecture comparison
- threat model
- trust boundaries
- security invariants
- protocol options
- PKI design
- component boundaries
- technology recommendations
- ADRs

Identify unresolved decisions.

PHASE 1 — REPOSITORY AND QUALITY FOUNDATION

Create:

- repository structure
- CI
- linting
- formatting
- testing harness
- security scanning
- dependency policy
- docs structure
- development environment

PHASE 2 — CONTROLLER DOMAIN MODEL

Implement core data model:

- users
- devices
- connectors
- resources
- grants
- certificate metadata
- sessions
- audit events

Do not yet expose real networks.

PHASE 3 — PKI AND ENROLLMENT

Implement device-generated keys, enrollment, issuance, expiry and revocation.

Test aggressively.

PHASE 4 — POLICY ENGINE

Implement default-deny resource authorization.

PHASE 5 — CONNECTOR PROTOTYPE

Use an isolated test network.

Allow only explicit resources.

PHASE 6 — LINUX CLIENT

Begin with Linux/Arch.

PHASE 7 — DASHBOARD

Material Design 3.

Implement secure bootstrap, users, devices, resources, access, connectors,
audit and security settings.

PHASE 8 — WINDOWS

Windows client.

Then Windows connector.

PHASE 9 — ANDROID CLIENT

Implement supported Android client.

Do not require an Android connector.

PHASE 10 — NETWORK HARDENING

Docker, LAN isolation, IPv6, NAT and hostile network tests.

PHASE 11 — MULLVAD AND DNS COMPATIBILITY

Perform dedicated coexistence testing.

PHASE 12 — SSH CERTIFICATE INTEGRATION

Optional integrated SSH CA.

PHASE 13 — UPDATE SYSTEM

Signed releases, compatibility and rollback.

PHASE 14 — SECURITY AUDIT / HARDENING

Run full acceptance suite.

Perform manual threat-model review.

Review all custom security-sensitive code.

Do not mark Portico production-ready merely because features work.

======================================================================
34. TECHNOLOGY SELECTION
======================================================================

Before committing to the implementation language/framework, compare sensible
options.

Evaluate particularly:

- memory safety
- networking ecosystem
- TLS/mTLS ecosystem
- cross-platform support
- Android integration
- Windows support
- maintainability
- static binaries / deployment
- dependency security

Rust and Go are obvious candidates for the security/networking core, but
do not select one solely because this prompt names them.

Write an ADR explaining the choice.

For the dashboard, choose a maintainable web technology capable of good
Material Design 3 support.

Avoid forcing the data-plane networking core into a web runtime.

======================================================================
35. NO PROPRIETARY IDENTITY DEPENDENCY
======================================================================

The default installation must NOT require:

- Google login
- Microsoft login
- GitHub login
- email
- hosted OIDC
- proprietary cloud authentication

External identity-provider integration may be an optional later feature.

The built-in certificate/FIDO2 identity system must remain capable of
operating independently.

======================================================================
36. DEPLOYMENT SAFETY
======================================================================

Never instruct an automated installer to immediately replace production
firewall rules without protection.

Networking changes should support:

- dry run
- effective-policy preview
- configuration validation
- backup
- timed rollback where appropriate
- console recovery
- health verification before persistence

Do not automatically enable router DMZ.

Do not automatically configure UPnP/NAT-PMP.

Manual, explicit forwarding should be documented for deployments requiring
public ingress.

======================================================================
37. DEFINITION OF MVP
======================================================================

The first genuinely useful MVP should provide:

- self-hosted controller
- Docker Compose deployment
- Ubuntu/Linux connector
- Arch/Linux client
- Windows client
- Android client
- certificate-backed device enrollment
- administrator FIDO2 protection for sensitive actions
- users
- devices
- resources
- resource grants
- revocation
- expiry
- default-deny policy
- audit logs
- Material Design dashboard
- safe bootstrap
- basic update/version visibility
- complete security documentation
- automated security acceptance tests

Windows connector can follow immediately afterward if implementing it in
the first MVP materially delays the security-critical core.

Android connector is explicitly optional.

======================================================================
38. DEFINITION OF "DONE"
======================================================================

"Feature complete" does not mean "secure".

Portico is not considered production-ready until:

1. The threat model matches the implementation.

2. Security acceptance tests pass.

3. Default deny is demonstrated.

4. Resource isolation is demonstrated.

5. Revocation works.

6. Session termination works.

7. Recovery works.

8. LAN isolation works in supported deployments.

9. Docker cannot trivially bypass isolation.

10. IPv6 cannot trivially bypass isolation.

11. Mullvad coexistence is tested.

12. DNS behavior is tested.

13. Client binaries/releases are authenticated.

14. Dependencies have been reviewed/scanned.

15. Documentation describes real behavior.

16. No known critical/high security findings remain unresolved.

======================================================================
39. FIRST TASK
======================================================================

DO NOT immediately write the entire application.

Start with Phase 0.

Inspect the requirements in this prompt carefully.

Then create the initial repository design package:

1. PROJECT_BRIEF.md
2. ARCHITECTURE.md
3. THREAT_MODEL.md
4. SECURITY_INVARIANTS.md
5. TRUST_BOUNDARIES.md
6. COMPETITOR_ARCHITECTURE_REVIEW.md
7. PKI_DESIGN.md
8. RESOURCE_MODEL.md
9. SESSION_AND_REVOCATION_DESIGN.md
10. BOOTSTRAP_AND_RECOVERY.md
11. PLATFORM_SUPPORT.md
12. NETWORK_AND_MULLVAD_DESIGN.md
13. DNS_DESIGN.md
14. UPDATE_SECURITY.md
15. ACCEPTANCE_TEST_PLAN.md
16. ADR-001-implementation-language.md
17. ROADMAP.md

Identify unresolved questions rather than inventing unsafe assumptions.

Research mature implementations where appropriate.

For every proposed security-critical mechanism, state:

- threat being addressed
- mechanism
- trusted component
- failure mode
- recovery path
- test that proves it

After the Phase 0 design package is internally consistent, summarize:

- architecture chosen
- unresolved decisions
- security risks
- recommended implementation language
- recommended next phase

STOP at the end of Phase 0 and wait for explicit authorization before
starting implementation.

Portico's design philosophy is:

    Simple access model.
    Explicit identity.
    Explicit resources.
    Default deny.
    No lateral movement.
    No unnecessary cloud dependency.
    No private-key escrow.
    Strong administrative authentication.
    Safe recovery.
    Standard cryptography.
    Security proven by tests rather than assumed.