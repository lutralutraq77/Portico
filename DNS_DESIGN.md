# DNS design

Status: Phase 0. Default: do not change DNS.

## Baseline
Resources work through explicit local client bindings and connector-side IP/address + port. No system resolver replacement, global hosts-file edits, DNS search suffix changes, DoH interception or Mullvad DNS override. Existing public DNS continues through the user's chosen resolver/VPN configuration.

Client catalog contains only assigned resources. A displayed hostname is metadata until authenticated authorization confirms the exact resource revision.

## Hostname resources and rebinding
A hostname can resolve to an unauthorized management target, cloud metadata endpoint, new host or another address family. DNS validity is not application authenticity. OWASP recommends addressing both validation and DNS-related SSRF risks. [SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

Proposed initial hostname policy:
1. Administrator enters one hostname and port. No wildcard/CIDR/suffix matching.
2. Connector resolves through its configured resolver. Preview all candidate A/AAAA addresses and canonical hostname information.
3. Apply address normalization and protected-target exclusions to every candidate.
4. Fresh approval stores the exact permitted concrete IP set in a new resource revision.
5. On a new connection, resolve once, intersect with approved IPs, and fail closed if answers are unapproved or ambiguous. No implicit expansion; mixed approved/unapproved answers require review.
6. Pin the chosen IP for the session and dial that literal socket. No later library hostname re-resolution, HTTP redirects or fallback addresses outside the approved set.
7. Controller and connector independently check membership and exact tuple. Changed answers pause new connections pending preview/reapproval.

This deliberately trades dynamic-DNS convenience for deterministic scope. Resource UI should show a clear “destination address changed; review required” status. Q04 owns IDNA/canonicalization, CNAME limits and multi-answer semantics before hostname support ships.

DNS poisoning can still impersonate a service at an approved IP. Application TLS/SSH verification is required. Portico identity does not authenticate Jellyfin or SSH itself.

## Failure
Resolver outage denies new hostname sessions; literal-IP resources remain usable. Existing approved sessions obey their original deadlines and do not retarget. No public fallback resolver is installed. NXDOMAIN, timeout, truncation, malformed answers, disallowed IPv6 or mixed unapproved answers never widen scope.

Expired pins or address changes require reviewed configuration, not disabling identity checks. DNS failure does not remove certificate identity or console recovery.

## Optional split DNS later
Opt-in only. Route queries for exact configured private suffixes through a Portico resolver; preserve all other resolver behavior. Never claim global `.local`, root `.`, or all public names. Suffix search ordering, overlapping user/VPN zones, per-link resolver APIs and restore-on-uninstall behavior need platform-specific qualification.

No global DNS ownership on Android as a workaround for the single-VPN restriction. Split DNS is out of MVP; DNS-04 tests its future zone confinement before it may ship.

## Proof and mechanism
DNS-01 captures before/after OS resolver, routes and DNS traffic on install/start/stop. DNS-02 rebinds an approved hostname to another port/host, metadata target and IPv6 target. DNS-03 races resolution versus dial and verifies literal-IP pinning and no unsafe fallback. DNS-04 tests opt-in suffix isolation/restoration.

Trusted components: controller's approved IP set, honest connector resolver/dial path, OS resolver implementation. Failure: deny new hostname access. Recovery: explicit reviewed resource revision or literal-IP configuration. CTRL-10 covers this mechanism.
