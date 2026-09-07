# Trust boundaries

Status: Phase 0. Boundary IDs map to [threats](THREAT_MODEL.md) and the [control matrix](SECURITY_CONTROL_MATRIX.md).

| ID | Crossing | Authenticity / authorization | Trust and failure containment |
|---|---|---|---|
| TB-01 | User application → local client | Per-resource local binding; OS user access controls where available | An ordinary TCP loopback socket is not per-user authentication. On shared hosts, other local users may use that listener; native IPC/stdio or stricter user isolation is needed. Q07 blocks stronger claims. |
| TB-02 | Hostile Internet → ingress | Server-authenticated TLS; mTLS on enrolled methods; quotas and fixed routes | Ingress is exposed only by explicit deployment configuration. It cannot dispatch arbitrary host:port targets or serve management. |
| TB-03 | Client → connector through relay | Inner TLS authenticates both endpoints; each new stream is authorized online | Relay identities, metadata and pair IDs are not client principal evidence. Relay cannot decrypt inner data. Compromised endpoint is outside this protection. |
| TB-04 | Connector → controller | Connector mTLS plus role-specific methods; session requests carry identity observed on inner TLS | Honest connectors are trusted to report their directly verified client; compromise can falsify such reports within connector-hosted scope. Never claim containment stronger than the connector's actual network boundary. |
| TB-05 | Connector → destination | Exact reviewed tuple and validated IP; OS egress boundary; application auth | Connector can see plaintext when the underlying application is plaintext. Endpoint TLS/SSH authenticates the actual application. Same-network services need independent separation. |
| TB-06 | Browser / admin agent → management | Device-bound server authentication + fresh operation-bound WebAuthn for sensitive actions; CSRF and origin checks | A loopback address alone is not owner authentication. Untrusted headers and cookies alone cannot supply the certificate factor. Q02 requires a proven browser/agent design. |
| TB-07 | Controller → issuer | Dedicated mTLS or protected local socket, narrow issuance contract and server-side templates | Registration authority may request only approved profile/ID/key/lifetime. Online issuer compromise enables forgery in its trust scope; controller registry checks help but do not protect a compromised controller. |
| TB-08 | Controller → state/audit | Dedicated OS identity; transactions and restricted filesystem access | Root can alter local state. An outbox improves consistency, not root-proof immutability. Independent export provides detection for already-exported events. |
| TB-09 | Offline root / recovery operator → running system | Physical console ownership; explicitly staged trust/identity replacement | Host root/console is an intentional recovery authority. Remote root shells do not prove physical presence. Physical-presence assurance remains a deployment question Q06. |
| TB-10 | Release repository → installer | Independently trusted signed metadata and target hashes; version/expiry checks | CDN, DNS, mirrors and repository admin accounts are not release root authority. Signing quorum and rollback trust remain separate from Portico device CA. |
| TB-11 | Torrent namespace → network | Mullvad-only Internet egress, independent kill switch; no route through connector | Portico must not become an alternate gateway. Changes to the existing host VPN are outside automated installation scope. |
| TB-12 | Backup media → recovered controller | Authenticated encryption, manifest validation, isolated restore, new trust state as required | Authentic old data may still be dangerously stale. Integrity verification alone does not resolve rollback of revocations. |

## Secret and metadata ownership
Device private keys stay with clients. Connector keys stay with connectors. Online intermediate keys stay in the issuer's protected storage. Root and release-signing private keys are offline and distinct. Controller storage contains public certificates, WebAuthn public keys, hashed invitation verifiers, state, and audit metadata.

Resource addresses and usage patterns are sensitive metadata. Clients see only assigned catalog entries; connectors see only their hosted resources. Relay routing necessarily reveals timing, traffic sizes and selected connector. Controller authorization reveals principal/resource associations. No promise of traffic-analysis resistance is made.

## Separation that must survive deployment
Do not mount the Docker socket or issuer secrets into connectors or relay. A read-only container root filesystem does not make a shared writable secret volume safe. A dual-homed connector is not a router; it must lack forwarding authority. A management connector belongs to an independently restricted network and OS identity.

Controller administration is a high-trust boundary even when reached through Portico itself. Losing the management connector must not remove physical recovery. A public hostname, IPv6 route or container publication must not bypass the private management entry point.

## Compromise combinations
- Malicious client + honest connector: server-side tuple enforcement must hold.
- Malicious relay + honest endpoints: authentication/confidentiality must hold; availability is lost.
- Malicious connector + honest controller: connector cannot create policy/admins, but can abuse or expose its reachable workloads.
- Compromised application: its own egress restrictions determine possible pivots.
- Controller root or controller + issuer compromise: policy enforcement cannot be trusted; quarantine and rebuild.
- Both device certificate and hardware key compromised: independent local recovery and revocation are required; MFA does not provide further magic protection.
