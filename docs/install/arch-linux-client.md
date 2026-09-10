# arch linux client

The [Arch development package workflow](../arch-development-package.md) passed its pinned-container build, install, command, remove and separate-state-preservation checks. The later [agent catalog source](../phase-6-agent-evidence.json), `e1b3575ae4fb2b69905cf3f3b7075af93ac3f568`, also passed that workflow. The package contains the development command and manual for isolated testing. The [agent](../agent-catalog.md) runs as an explicitly unlocked foreground process; [resource streaming](../agent-resource-streams.md) has separate qualification evidence. Installed services, supported release distribution and real desktop/application qualification remain pending.

See [platform requirements](../../PLATFORM_SUPPORT.md), [network assumptions](../../NETWORK_AND_MULLVAD_DESIGN.md) and [development setup](../development.md). Installation instructions will be added only with the actual implementation and platform qualification.
