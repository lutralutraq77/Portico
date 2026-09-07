# Isolated network test environment plan

No lab is started by Phase 1 setup. Before running later network tests, provision disposable VMs or an equivalent separately controlled test host with dedicated test networks.

Required roles: controller/issuer, ingress, two connectors, dual-stack resources, untrusted LAN client, owned Internet sink and separate Mullvad/torrent workload domain. Production credentials, real router forwarding and developer host firewall/VPN state are excluded.

Default external exposure is none. Permit downloads only through controlled development egress. Resource-network tests require explicit scope and disposable fixtures. No UPnP, DMZ, public DNS mutation or public scanning.

Capture before/after interface, route, resolver, listener and firewall state. Pair denial probes with positive controls. Keep packet captures free of real secrets and retain version/topology metadata. Real Mullvad qualification later uses owned harmless payloads and separate test configuration.

Read [network/Mullvad design](../NETWORK_AND_MULLVAD_DESIGN.md), [trust boundaries](../TRUST_BOUNDARIES.md) and [acceptance plan](../ACCEPTANCE_TEST_PLAN.md) before provisioning. This plan is not evidence of Docker/LAN isolation or a running Compose deployment.
