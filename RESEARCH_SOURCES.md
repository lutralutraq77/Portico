# Research sources and provenance

Research date: 7 September 2026. These are primary project/vendor/standards sources. Claims in the design distinguish documented upstream behavior from Portico proposals. No source was treated as proof of a secure Portico implementation.

Web documentation is mutable. Source-code observations below are pinned to inspected commits. Exact dependency versions, support policies, licensing and vulnerability status must be reviewed again before implementation.

| Ref | Primary source | What was reviewed / relevance |
|---|---|---|
| S01 | [Twingate architecture](https://www.twingate.com/docs/how-twingate-works/) | Resource/controller/client/connector/relay concepts; product documentation, not OSS source evidence |
| S02 | [Twingate connection flow](https://www.twingate.com/docs/detailed-client-connection-flow) | Per-resource connection authorization and identity binding |
| S03 | [OpenZiti service policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/creating-service-policies/) | Distinct Dial and Bind permissions |
| S04 | [OpenZiti service policy model, pinned](https://github.com/openziti/ziti/blob/b271a9e48d32dcba596a33f5301196c8bb6138a1/controller/model/service_policy_model.go) | Policy type validation and mapping |
| S05 | [OpenZiti session manager, pinned](https://github.com/openziti/ziti/blob/b271a9e48d32dcba596a33f5301196c8bb6138a1/controller/model/session_manager.go) | Identity-scoped service lookup and permission checks |
| S06 | [NetBird routing peers](https://docs.netbird.io/manage/networks/how-routing-peers-work) | Separation of resource forwarding from access to routing peer itself; Networks/Routes distinction |
| S07 | [Teleport per-session MFA](https://goteleport.com/docs/zero-trust-access/authentication/per-session-mfa/) | Fresh factor checks against certificate theft |
| S08 | [Teleport session/identity locking](https://goteleport.com/docs/identity-governance/locking/) | Dynamic locks and strict versus stale-state behavior; page labels Enterprise availability |
| S09 | [Smallstep CA production guidance](https://smallstep.com/docs/step-ca/certificate-authority-server-production/) | Offline root, intermediate custody, operational renewal/revocation considerations |
| S10 | [Smallstep revocation](https://smallstep.com/docs/step-ca/revocation/) | Passive renewal denial versus active revocation; avoid assuming either terminates Portico streams |
| S11 | [Smallstep renewal handler, pinned](https://github.com/smallstep/certificates/blob/bb481fbf670c24721d5bdb1489ad0d1052c203b5/api/renew.go) | Certificate/token renewal entry paths need Portico integration controls |
| S12 | [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) | Default-deny and checks at every authorization entry point |
| S13 | [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Destination/address validation and DNS rebinding concerns |
| S14 | [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Browser session controls; certificate identity remains a separate requirement |
| S15 | [W3C WebAuthn](https://www.w3.org/TR/webauthn-3/) | RP/origin scope, assertions, UV and authenticator/backup properties; not a universal proof of hardware independence |
| S16 | [TLS 1.3, RFC 9846](https://www.rfc-editor.org/info/rfc9846/) | Current RFC Editor TLS 1.3 reference found through RFC 8446's obsolescence notice |
| S17 | [gRPC core concepts](https://grpc.io/docs/what-is-grpc/core-concepts/) | RPC streaming lifecycle; does not provide Portico reverse-stream authorization automatically |
| S18 | [Android VPN](https://developer.android.com/develop/connectivity/vpn) | One active VPN service per user/profile and lifecycle constraints |
| S19 | [Android Keystore](https://developer.android.com/privacy-and-security/keystore) | OS-controlled local key material and hardware capability considerations |
| S20 | [Microsoft CNG key storage providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers) | Provider separation and platform/TPM-backed key facilities |
| S21 | [Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/) | Published-port versus host firewall packet paths |
| S22 | [Docker nftables backend](https://docs.docker.com/engine/network/firewall-nftables/) | Backend-specific chains/hook migration; experimental status in inspected docs |
| S23 | [Mullvad split tunneling](https://mullvad.net/en/help/split-tunneling-with-the-mullvad-app) | Excluded apps bypass VPN; broad exclusion is not a safe generic fix |
| S24 | [Go TLS API](https://pkg.go.dev/crypto/tls) | Certificate verification/connection APIs; explicit revocation remains application work |
| S25 | [Go crypto.Signer](https://pkg.go.dev/crypto#Signer) | External signing abstraction, not an automatic OS-key implementation |
| S26 | [Go security](https://go.dev/doc/security/) | Available security tooling for later dependency/CI selection |
| S27 | [Go mobile tooling](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile) | Mobile build/binding candidate; not proof of Android Keystore interoperability |
| S28 | [rustls](https://github.com/rustls/rustls) | Rust TLS alternative and provider/dependency review surface |
| S29 | [Angular Material theming source](https://raw.githubusercontent.com/angular/components/main/guides/theming.md) | Material design tokens/theme integration; public web guide itself returned no text |
| S30 | [Material Web repository](https://github.com/material-components/material-web) | Maintenance-mode notice relevant to UI library selection |
| S31 | [TUF specification](https://theupdateframework.github.io/specification/latest/) | Role-separated signed metadata, freshness and rollback protection |
| S32 | [age project](https://github.com/FiloSottile/age) | Existing encrypted backup format/tool candidate; no dependency version selected |

## Research method and limits
Inspected selected official documentation and narrow upstream source paths. OpenZiti and Smallstep repository revisions were resolved through the public GitHub API and the named files read locally for the specific observations above. Temporary source snapshots reside under work/ on E: and are not intended to be published or vendored.

No network/PKI software was installed, no interoperability benchmark ran, no licensing opinion was made and no upstream project underwent a complete code audit. Version/backend-dependent findings must be rechecked at qualification time.

Material UI support and mobile/OS-key bridges need implementation-specific validation. Mullvad namespace isolation, Portico's 15-second lease policy, exact IP pinning and operation state machines are Portico proposals, not claimed upstream defaults.

The original user requirements are preserved in [requirements/PORTICO_MASTER_PROMPT.md](requirements/PORTICO_MASTER_PROMPT.md). Future public publication should review that file for local context and the intended repository license rather than blindly publishing every development artifact.
