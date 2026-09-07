# Policy API implementation

Phase 4 implements a private controller HTTP component. A deployable controller/client/connector system is still being built. The main portico executable remains help/version only; no listener is started by constructing a PolicyEngine.

All routes below require POST, Content-Type application/json, exact configured Host, bounded JSON and a live TLS 1.3 client certificate of the corresponding profile. No route accepts proxy identity headers. Administrator routes additionally require the configured exact HTTPS Origin and registered administrator authority. Server responses use exported DTO field names shown below; the v1 path selects the API contract, and connector messages additionally require Version=1.

| Profile | Route | Request and behavior |
|---|---|---|
| Device | /api/v1/device/catalog | Empty object; returns only usable application resources for the authenticated device, current revisions and deadlines |
| Connector | /api/v1/connector/authorize | Version, ClientLeafDER (base64), ResourceID, Revision; derives the exact endpoint and allocates a session after online checks |
| Connector | /api/v1/connector/activate | Version, SessionID, Sequence; rechecks live authority before application forwarding can begin |
| Connector | /api/v1/connector/renew | Same fields; active session only, exact sequence, original certificate/grant/binding and current policy required |
| Connector | /api/v1/connector/close | Version, SessionID, Sequence; closes only a session owned by the same connector certificate; sequence is not authority for closure |
| Administrator | /api/v1/admin/policy/preview | Exactly one Resource, Grant or Hosting draft; ResourceID/ExpectedRevision accepted only for endpoint revision |
| Administrator | /api/v1/admin/policy/challenge | ID and Digest of an owned current preview; starts operation-bound WebAuthn approval |
| Administrator | /api/v1/admin/policy/confirm | ID of the challenge and Response containing the WebAuthn JSON; consumes the exact stored operation atomically |

Resource draft fields are Name, ConnectorID, Address, Port and Protocol. Grant fields are UserID, DeviceID, ResourceID, Revision, From and Until. Hosting fields are ConnectorID, ResourceID, Revision, From and Until. Times use JSON RFC3339 timestamps. IDs, enabled flags, resource kind and approval references are server-generated. No grant or hosting permission is inferred from creating a resource.

Authorization responses identify the exact session/device/connector/certificates, effective Resource, Sequence, PolicyRevision and IssuedAt/LeaseUntil/ActivateUntil/SessionUntil. A response is not a bearer token. The connector must first prove the device key through inner TLS, dial only the returned endpoint, obtain activation before forwarding and enforce request-start-anchored deadlines and cancellation. That transport enforcement is separate work; controller response timestamps alone cannot prove termination.

Every rejection uses HTTP 403 with a fixed request-rejected JSON object and no reflected input. Runtime logging/correlation integration and complete operator-facing errors remain service work. Mutations are not automatically retried after an uncertain response. Close currently returns a rejection for an already closed session; callers still close their local socket regardless of the controller result.

See [ADR-005](../ADR-005-resource-policy-boundary.md) for preview freshness, quotas, schema migration and remaining security gates. The administrator server is tested with isolated virtual keys and an explicit test origin; this is not evidence of browser/native or hardware qualification.
