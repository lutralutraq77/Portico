# Platform support and compatibility

Status: design targets only. No platform is currently supported by a shipped Portico implementation.

## Matrix
| Platform | Required role / milestone | Proposed integration | Qualification gate |
|---|---|---|---|
| Arch Linux | MVP client, Phase 6 | Go core; explicit local resource forwarding; package/service integration | Rolling dependency testing, desktop key storage, Mullvad coexistence |
| Modern Linux | MVP client | Same core; distribution-neutral OS adapters | Supported distro/kernel/libc matrix and shared security tests |
| Ubuntu Server/Linux | MVP connector/controller | Unprivileged service processes and isolated network profile | Service hardening, recovery console, dual-stack egress |
| Docker/Compose on Linux | MVP controller/connector deployment | Separate service identities, mounts and private networks | NET-01–08; exact Engine/backend versions; no host networking assumption |
| Windows | MVP client, Phase 8 | Go service/agent plus CNG key provider; per-user IPC | Key non-exportability mode, service SID/ACLs, local-user isolation, suspend |
| Windows | Connector, Phase 8 or immediately after MVP | Same policy semantics, restricted service identity/egress | Hosting without admin rights; Windows firewall/profile testing |
| Android | MVP client, Phase 9 | Kotlin UI/Keystore/service lifecycle; shared core only through proven binding | One-VPN limitation, Doze/suspend/reconnect, Keystore signing and actual apps |
| Android | Optional experimental connector | No design commitment | Separate future threat model; never blocks required Android client |

Minimum versions, CPU architectures and exact support windows remain Q11. Proposed first qualification: Linux/Windows x86_64 and Android arm64; ARM Linux should be evaluated for self-hosted hardware. Do not advertise unsupported builds based solely on successful cross-compilation.

## Access modes
Baseline desktop client offers a local binding for a selected resource, or stdio/OS-protected IPC for applications such as SSH. No TUN, default route or global DNS change is required.

A TCP loopback socket is accessible to other local processes and often other OS users. Device identity represents the device; an optional single-user local forwarding mode must disclose that scope. Shared-machine guarantees require OS-authenticated IPC, per-user isolation or a qualified platform filter. Q07 must close before claiming user isolation. Local malware can use legitimate device access even with a hardware key provider.

Local forwarding does not preserve arbitrary application hostname/TLS behavior automatically. Prefer applications that accept an explicit host/port or proxy configuration. HTTPS applications may require preserving expected server names. Record tested application workflows; do not disable certificate validation to make an app work.

## Android and Mullvad
Android documents only one active VPN service per user/profile; starting another replaces it. Portico cannot promise simultaneous Portico VpnService and Mullvad VpnService in the same profile. [Android VPN guidance](https://developer.android.com/develop/connectivity/vpn).

Required Android MVP direction: resource-specific local proxy/application integration for compatible applications, using ordinary sockets without taking the VPN slot. Verify Jellyfin/browser/SSH workflows and foreground-service/background behavior on real devices. Mullvad lockdown or app routing can still block connectivity; this is a test gate, not a guaranteed bypass.

An optional VpnService mode may later capture only selected resource destinations when it is the active VPN, with explicit user consent. It must not silently disconnect Mullvad. Work profiles are a distinct deployment option, not a universal two-VPN solution. Unsupported combinations show a clear limitation; never disable protection automatically.

Android Keystore provides local key protection, with hardware capability varying by device. Use native key handles; verify that the Go/Kotlin boundary can invoke signing without exporting private keys. [Android Keystore](https://developer.android.com/privacy-and-security/keystore).

## Windows and Linux keys
Windows CNG separates providers and key storage, including TPM-backed facilities. A CNG-backed signer bridge must be tested; compiling Go for Windows does not automatically use TPM keys. [Microsoft CNG providers](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers).

Linux baseline can use restrictive file permissions with encrypted storage, plus optional TPM/PKCS#11 providers after review. Hardware-unavailable status is explicit. Key protection may differ, but identity, grants, revocation and admin hardware-factor semantics cannot weaken.

## Compatibility contract
Protocol/API have explicit major versions. Within a major, optional additive fields/capabilities may be negotiated. Unknown authorization-critical fields, required capabilities and enums are rejected. No silent fallback to broad access or missing revocation features.

Initial support contract: same protocol major and all required security capabilities. Do not promise N±1 compatibility until tested. Controller displays versions and exact incompatibility reason. Older incompatible clients fail closed with a recovery/update path that does not require expired authority.

Platform-specific adapters must run the shared malicious-peer and expiry fixtures. Cross-compile results, emulator tests and real-device tests are separate evidence. PLATFORM-01–04 cover parity, local access scope, OS key providers and background/suspend behavior.
