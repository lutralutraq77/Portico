# arch linux client

The [Arch development package workflow](../arch-development-package.md) passed its pinned-container build, install, command, remove and separate-state-preservation checks. The [streaming source](../phase-6-stream-evidence.json) also passed that workflow. The package now includes the [locked daemon and inactive user unit](../agent-daemon.md); source `dbeda84b345ce783aaafb8479a2efbe99cbfc35e` passed the added unit's package checks. [Actual systemd user-manager qualification](../arch-user-service.md), supported release distribution and real desktop/application qualification remain pending.

See [platform requirements](../../PLATFORM_SUPPORT.md), [network assumptions](../../NETWORK_AND_MULLVAD_DESIGN.md) and [development setup](../development.md). Installation instructions will be added only with the actual implementation and platform qualification.
