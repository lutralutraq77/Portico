# Phase 6 encrypted resource-client integration

The development Linux resource client can use the encrypted key and retained certificate produced by the enrollment command. Version-2 client configuration points to approved public enrollment configuration and obtains its password from the dedicated descriptor-3 secret pipe. Version 1 retains its explicit software-key paths. Mixed modes, missing unlock material and failed validation reject without plaintext fallback. The [command contract](client-configuration.md) describes both modes.

The loader checks independent device trust before decryption, then verifies the retained certificate against the original enrollment bindings and local key. One normalized identity supplies control, carrier and inner TLS. Loading does not redeem, activate, generate or rewrite enrollment state. Fresh server authentication and policy determine whether the identity is currently active and authorized.

## Verification

Native configuration tests passed for strict mode separation, a single identity across all three TLS layers, rejection of invalid keys/certificates and absence of plaintext reads. The controller's reused HTTPS enrollment fixture also passed after normalizing its approved expiry to whole seconds. The Linux controller test binary compiled successfully. The command unit suite, new runtime scenario and final-source hosted qualification must be recorded separately before claiming complete qualification.

The new guarded `TestWorkloadGuestEncryptedClientEnrollmentAndRevocation` scenario executes actual enrollment and resource-client processes against the same controller store, production HTTPS handlers, carrier and workload protocol. It removes the earlier fixture's plaintext client identity, uses independent application and secret pipes, checks activation gating, exact catalog tuples, wrong passwords, mixed configuration, changed trust, unknown secret fields and denied resource selections, then transfers binary application bytes and revokes the enrolled credential. It requires the destination to close, a durable closure receipt, rejection from a fresh process, and unchanged encrypted/certificate files with exactly one additional signature.

The scenario uses the existing NIC-less guest guard, a synthetic 20 ms connector clock provider and explicitly installed/restored synthetic synchronization metadata in the disposable kernel for the real CLI. The connector's first binding starts when the unlocked client's catalog request reaches the test-owned HTTP handler, avoiding a race between the production password KDF and the idle binding lifetime. The actual catalog, TLS and authorization handlers run normally; no production deadline or retry behavior is changed. This is component/runtime evidence, not qualification of real clock synchronization, hardware key custody, physical power loss or full platform parity.

## Remaining work

An interactive launcher, desktop integration, installed services and Arch packaging remain required. Windows/Android key providers, actual administrator hardware keys and private hostname, dashboard, network/VPN qualification, signed releases and independent audit remain within the full fifteen-phase objective. The canonical manifest still records seven implemented cases and 84 planned; this increment promotes none.
