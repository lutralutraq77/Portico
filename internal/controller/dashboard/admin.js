"use strict";

(() => {
  const sections = {
    issuers: { title: "Enrollment issuers", description: "Bound ordinary-device and connector issuers.", columns: [["Issuer", "ID"], ["Profile", "Profile"], ["Fingerprint", "Fingerprint"], ["Expires", "NotAfter"], ["Configuration", "Enabled"]], fields: { ID: "string", Profile: "string", Fingerprint: "string", RootFingerprint: "string", Enabled: "boolean", NotAfter: "date" } },
    factors: { title: "Security keys", description: "Attested keys registered to the administrator using this connection.", columns: [["Key record", "ID"], ["Attested model", "ModelID"], ["Configuration", "Enabled"], ["Key test", "Tested"]], fields: { ID: "string", ModelID: "string", Enabled: "boolean", Tested: "boolean" }, scopeTitle: "Keep a tested backup key available.", scopeDescription: "Retiring a key requires a different tested key. Registration must be followed by a separate key test. These records do not prove physical recovery readiness.", loaded: "Your security-key records loaded." },
    users: { title: "Users", description: "People registered in this deployment.", columns: [["Person", "Name", "ID"], ["Configuration", "Enabled"]], fields: { ID: "string", Name: "string", Enabled: "boolean" } },
    devices: { title: "Devices", description: "Registered devices and the identities they belong to.", columns: [["Device", "Name", "ID"], ["User", "UserID"], ["Platform", "Platform"], ["Identity expires", "NotAfter"], ["Configuration", "Enabled"]], fields: { ID: "string", UserID: "string", Name: "string", Platform: "string", Enabled: "boolean", NotAfter: "date" } },
    resources: { title: "Resources", description: "The current revision of each explicitly defined destination.", columns: [["Resource", "Name", "ID"], ["Destination", "Address", "Port"], ["Connector", "ConnectorID"], ["Kind / protocol", "Kind", "Protocol"], ["Revision", "Revision"], ["Configuration", "Enabled"]], fields: { ID: "string", Revision: "number", Name: "string", ConnectorID: "string", Kind: "string", Address: "string", Port: "number", Protocol: "string", Enabled: "boolean" } },
    connectors: { title: "Connectors", description: "Registered connectors. Enabled does not indicate that a connector is online.", columns: [["Connector", "Name", "ID"], ["Reported version", "Version"], ["Configuration", "Enabled"]], fields: { ID: "string", Name: "string", Version: "string", Enabled: "boolean" } },
    enrollments: { title: "Enrollments", description: "Enrollment progress and expiry, without invitation secrets.", columns: [["Enrollment", "ID"], ["Principal", "PrincipalID"], ["Profile / state", "Profile", "State"], ["Invitation expires", "ExpiresAt"], ["Identity expires", "NotAfter"], ["Issuer", "IssuerID"]], fields: { ID: "string", IssuerID: "string", PrincipalID: "string", Profile: "string", State: "string", ExpiresAt: "date", NotAfter: "date" } },
    certificates: { title: "Certificates", description: "Issued identity fingerprints, expiry and revocation state.", columns: [["Certificate", "ID", "Fingerprint"], ["Principal / profile", "PrincipalName", "Profile"], ["Valid from", "NotBefore"], ["Expires", "NotAfter"], ["Revocation", "Revoked"], ["Issuer", "IssuerID"]], fields: { ID: "string", IssuerID: "string", PrincipalID: "string", PrincipalName: "string", Fingerprint: "string", Profile: "string", NotBefore: "date", NotAfter: "date", Revoked: "boolean" } },
    grants: { title: "Device grants", description: "Stored grants for exact device and resource revisions. Expired or disabled rules do not grant access.", columns: [["User / device", "UserName", "DeviceName"], ["Resource", "ResourceName", "ResourceID"], ["Revision", "Revision"], ["From", "From"], ["Until", "Until"], ["Configuration", "Enabled"]], fields: { ID: "string", UserID: "string", UserName: "string", DeviceID: "string", DeviceName: "string", ResourceID: "string", ResourceName: "string", Revision: "number", Enabled: "boolean", From: "date", Until: "date" } },
    hosting: { title: "Connector hosting", description: "Stored hosting permission for exact connector and resource revisions. Hosting alone gives no device access.", columns: [["Connector", "ConnectorName", "ConnectorID"], ["Resource", "ResourceName", "ResourceID"], ["Revision", "Revision"], ["From", "From"], ["Until", "Until"], ["Configuration", "Enabled"]], fields: { ID: "string", ConnectorID: "string", ConnectorName: "string", ResourceID: "string", ResourceName: "string", Revision: "number", Enabled: "boolean", From: "date", Until: "date" } },
    audit: { title: "Audit", description: "Recorded changes in sequence order, with actor and target identifiers.", columns: [["Event", "Action", "ID"], ["Occurred", "OccurredAt"], ["Actor", "ActorID"], ["Target", "TargetID"], ["Sequence", "Sequence"], ["Event hash", "Hash"]], fields: { ID: "string", ActorID: "string", CorrelationID: "string", Action: "string", TargetID: "string", PreviousHash: "string", Hash: "string", Sequence: "number", Generation: "number", OccurredAt: "date" }, scopeTitle: "Read the recorded history.", scopeDescription: "Events are shown oldest first. Viewing a page does not export or acknowledge the audit log. An independently retained checkpoint is needed to detect a rewritten history.", loaded: "Audit records loaded in sequence order." },
    security: { title: "Security", description: "The administrator identity used for this connection and its recorded factor status.", columns: [["Administrator", "UserName", "ID"], ["Device", "DeviceName", "DeviceID"], ["Certificate fingerprint", "CertificateFingerprint"], ["Certificate expires", "CertificateExpiresAt"], ["Enabled factors", "EnabledFactors"], ["Tested enabled factors", "TestedEnabledFactors"], ["Initial registration deadline", "BootstrapUntil"]], fields: { ID: "string", UserName: "string", DeviceID: "string", DeviceName: "string", CertificateFingerprint: "string", CertificateExpiresAt: "date", BootstrapUntil: "date", EnabledFactors: "number", TestedEnabledFactors: "number" }, scopeTitle: "Factor records describe configuration.", scopeDescription: "Counts do not prove separate physical keys or recovery readiness. A registration deadline does not grant permission to add a factor.", loaded: "Current administrator metadata loaded." },
    access: { title: "Inspect access", description: "Check the current policy for an exact pair of identities and a resource revision." }
  };
  const byID = (id) => document.getElementById(id);
  const records = byID("records");
  const feedback = byID("feedback");
  const inventory = document.querySelector(".inventory");
  const nextButton = byID("next");
  const previousButton = byID("previous");
  let section = "users", revision = 0, next = "", cursors = [""], pageIndex = 0;
  let pending, generation = 0;
  const accessViews = ["access", "grants", "hosting"];
  const securityViews = ["security", "factors"];
  const lifecycleEntities = { users: "user", devices: "device", connectors: "connector" };
  const choiceTypes = {
    device: { label: "Device certificate", section: "certificates", profile: "device" },
    connector: { label: "Connector certificate", section: "certificates", profile: "connector" },
    resource: { label: "Resource", section: "resources", profile: "" }
  };
  let choices = {};
  let policy = null;
  let factor = null;
	let secretCleanup;

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function message(text, error = false) {
    feedback.textContent = text;
    feedback.dataset.error = String(error);
  }
  function clear() {
    secretCleanup?.();
    policy = null;
    factor = null;
    records.replaceChildren();
    byID("revision").textContent = "";
    byID("page-summary").textContent = "Inventory unavailable";
    nextButton.disabled = true;
    previousButton.disabled = true;
  }
  function reset() {
    revision = 0; next = ""; cursors = [""]; pageIndex = 0;
    choices = Object.fromEntries(Object.keys(choiceTypes).map((key) => [key, { cursors: [""], index: 0, selected: "" }]));
    byID("page-number").textContent = "Page 1";
  }
  function cancel() {
    generation++;
    if (pending) pending.abort();
    pending = undefined;
  }
  function validPage(data, requestedSection, requestedRevision) {
    if (!data || data.Version !== 1 || data.Section !== requestedSection || !Number.isSafeInteger(data.PolicyRevision) || data.PolicyRevision < 1 ||
        (requestedRevision && data.PolicyRevision !== requestedRevision) || typeof data.ObservedAt !== "string" || !Number.isFinite(Date.parse(data.ObservedAt)) ||
        !Array.isArray(data.Items) || data.Items.length > 50 || typeof data.Next !== "string" || data.Next.length > 64) return false;
    const fields = sections[requestedSection].fields;
    const validItems = data.Items.every((item) => item && Object.keys(item).length === Object.keys(fields).length && Object.entries(fields).every(([key, type]) => {
      const value = item[key];
      if (type === "date") return typeof value === "string" && value.length < 64 && Number.isFinite(Date.parse(value));
      if (type === "number") return Number.isSafeInteger(value) && value >= 0;
      return typeof value === type && (type !== "string" || value.length <= 4096);
    }));
    if (!validItems) return false;
    if (requestedSection === "factors") return data.Items.every((item) => uuid(item.ID) && uuid(item.ModelID));
    const hash = (value) => /^[0-9a-f]{64}$/.test(value);
    if (requestedSection === "issuers") return data.Items.every((item) => uuid(item.ID) && ["device", "connector"].includes(item.Profile) && hash(item.Fingerprint) && hash(item.RootFingerprint));
    if (requestedSection === "security") return data.Items.length === 1 && data.Next === "" && data.Items.every((item) => hash(item.CertificateFingerprint) && item.TestedEnabledFactors <= item.EnabledFactors && Date.parse(item.CertificateExpiresAt) > Date.parse(data.ObservedAt));
    if (requestedSection === "audit") return (!data.Next || data.Next === data.Items.at(-1)?.ID) && data.Items.every((item, index) => item.Sequence > 0 && item.Generation > 0 && hash(item.Hash) && (item.Sequence === 1 ? item.PreviousHash === "" : hash(item.PreviousHash)) && (index === 0 || (item.Sequence === data.Items[index-1].Sequence + 1 && item.PreviousHash === data.Items[index-1].Hash)));
    return true;
  }
  function display(item, key) {
    if (key === "Tested") return item[key] ? "Test recorded" : "Needs key test";
    if (key === "Enabled") return item[key] ? "Enabled" : "Disabled";
    if (key === "Revoked") return item[key] ? "Revoked" : "Not revoked";
    if (sections[section].fields[key] === "date") return new Date(item[key]).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
    return String(item[key]);
  }
  function render(data) {
    const view = sections[section];
    const table = element("table");
    table.append(element("caption", `${view.title} · observed ${new Date(data.ObservedAt).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC")}`));
    const header = element("tr");
    for (const [label] of view.columns) {
      const cell = element("th", label); cell.scope = "col"; header.append(cell);
    }
    if (section === "resources" || section === "factors" || section === "enrollments" || Object.hasOwn(lifecycleEntities, section)) { const cell = element("th", "Manage"); cell.scope = "col"; header.append(cell); }
    const head = element("thead"); head.append(header); table.append(head);
    const body = element("tbody");
    for (const item of data.Items) {
      const row = element("tr");
      for (const [label, key, secondary] of view.columns) {
        const cell = element("td"); cell.dataset.label = label;
        const isBadge = key === "Enabled" || key === "Revoked";
        cell.append(element("span", display(item, key), isBadge ? "badge" : key === "Name" ? "record-title" : ""));
        if (secondary) cell.append(element("span", (secondary === "Port" ? "Port " : "") + display(item, secondary), "record-id"));
        row.append(cell);
      }
      if (section === "resources") {
        const cell = element("td"); cell.dataset.label = "Manage";
        const revise = element("button", "Revise"); revise.type = "button"; revise.disabled = !item.Enabled;
        revise.setAttribute("aria-label", `Revise ${item.Name}`);
        revise.addEventListener("click", () => startPolicy("revise-resource", item)); cell.append(revise); row.append(cell);
      }
      if (section === "factors") {
        const cell = element("td"); cell.dataset.label = "Manage";
        for (const [kind, label] of [["test-factor", "Test key"], ["disable-factor", "Retire key"]]) {
          const button = element("button", label); button.type = "button"; button.disabled = !item.Enabled;
          button.setAttribute("aria-label", `${label} ${item.ID}`);
          button.addEventListener("click", () => startFactor(kind, item)); cell.append(button);
        }
        row.append(cell);
      }
      if (section === "enrollments") {
        const cell = element("td"); cell.dataset.label = "Manage";
        const button = element("button", "Revoke enrollment"); button.type = "button"; button.disabled = item.State === "revoked";
        button.setAttribute("aria-label", `Revoke enrollment ${item.ID}`); button.addEventListener("click", () => startInvitation(item.Profile, item)); cell.append(button); row.append(cell);
      }
      if (Object.hasOwn(lifecycleEntities, section)) {
        const entity = lifecycleEntities[section], cell = element("td"); cell.dataset.label = "Manage";
        for (const [action, label] of [["rename", "Rename"], ["disable", "Revoke access"]]) {
          const button = element("button", label); button.type = "button"; button.disabled = !item.Enabled;
          button.setAttribute("aria-label", `${label} for ${entity} ${item.Name}`);
          button.addEventListener("click", () => startPolicy(`${action}-${entity}`, item)); cell.append(button);
        }
        row.append(cell);
      }
      body.append(row);
    }
    table.append(body);
    const wrapper = element("div", undefined, "table-wrap"); wrapper.append(table);
    records.replaceChildren(wrapper);
    if (section === "enrollments") {
      const bar = element("div", undefined, "policy-actions");
      for (const profile of ["device", "connector"]) { const button = element("button", `Invite ${profile}`, "primary-action"); button.type = "button"; button.addEventListener("click", () => startInvitation(profile)); bar.append(button); }
      records.prepend(bar);
    }
    const actions = { resources: ["Create resource", "create-resource"], grants: ["Add device grant", "grant"], hosting: ["Add hosting permission", "host"], users: ["Add user", "create-user"], devices: ["Add device", "create-device"], connectors: ["Add connector", "create-connector"] };
    if (Object.hasOwn(actions, section)) {
      const [label, kind] = actions[section], bar = element("div", undefined, "policy-actions");
      const button = element("button", label, "primary-action"); button.type = "button";
      button.addEventListener("click", () => startPolicy(kind)); bar.append(button); records.prepend(bar);
    }
    if (section === "factors") {
      const bar = element("div", undefined, "policy-actions");
      for (const [kind, label] of [["register-factor", "Add security key"], ["bootstrap-factor", "Initial key registration"]]) {
        const button = element("button", label); button.type = "button";
        button.addEventListener("click", () => startFactor(kind)); bar.append(button);
      }
      records.prepend(bar);
    }
    byID("page-summary").textContent = `${data.Items.length} ${data.Items.length === 1 ? "record" : "records"} on this page`;
    byID("revision").textContent = `Policy revision ${data.PolicyRevision}`;
    byID("page-number").textContent = `Page ${pageIndex + 1}`;
    message(data.Items.length ? (view.loaded || `${view.title} loaded. Configuration does not establish effective access.`) : `No ${section} to display.`);
  }
  async function load() {
    if (section === "access") return loadAccess();
    document.querySelector(".pagination").hidden = section === "security";
    cancel();
    const attempt = generation, requestedSection = section, requestedRevision = revision;
    clear();
    inventory.setAttribute("aria-busy", "true");
    byID("page-summary").textContent = "Loading inventory…";
    message(`Loading ${requestedSection}…`);
    const controller = new AbortController(); pending = controller;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch("/api/v1/admin/dashboard/inventory", {
        method: "POST", mode: "same-origin", credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json" }, signal: controller.signal,
        body: JSON.stringify({ Section: requestedSection, After: cursors[pageIndex], Limit: 50, PolicyRevision: requestedRevision })
      });
      if (!response.ok || response.headers.get("Content-Type") !== "application/json") throw new Error("Inventory rejected");
      const data = await response.json();
      if (!validPage(data, requestedSection, requestedRevision)) throw new Error("Invalid inventory");
      if (attempt !== generation) return;
      revision = data.PolicyRevision; next = data.Next;
      render(data);
      previousButton.disabled = pageIndex === 0;
      nextButton.disabled = !next;
    } catch {
      if (attempt !== generation) return;
      clear(); reset();
      message("Inventory could not be verified. Your access or the policy may have changed. Refresh to try again.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) { pending = undefined; inventory.setAttribute("aria-busy", "false"); }
    }
  }
  async function privateJSON(path, body, signal) {
    const response = await fetch(path, { method: "POST", mode: "same-origin", credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
    if (!response.ok || response.headers.get("Content-Type") !== "application/json") throw new Error("Request rejected");
    return response.json();
  }
  async function loadAccess() {
    cancel();
    const attempt = generation, requestedRevision = revision;
    clear(); inventory.setAttribute("aria-busy", "true");
    byID("page-summary").textContent = "Loading policy choices…";
    message("Loading registered identities and resources…");
    const controller = new AbortController(); pending = controller;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const pages = await Promise.all(Object.entries(choiceTypes).map(async ([key, type]) => {
        const state = choices[key];
        const page = await privateJSON("/api/v1/admin/dashboard/inventory", { Section: type.section, Profile: type.profile, After: state.cursors[state.index], Limit: 50, PolicyRevision: requestedRevision }, controller.signal);
        if (!validPage(page, type.section, requestedRevision) || (type.profile && page.Items.some((item) => item.Profile !== type.profile))) throw new Error("Invalid choices");
        return [key, page];
      }));
      if (attempt !== generation) return;
      if (pages.some(([, page]) => page.PolicyRevision !== pages[0][1].PolicyRevision)) throw new Error("Policy changed");
      revision = pages[0][1].PolicyRevision;
      renderAccess(Object.fromEntries(pages));
      byID("page-summary").textContent = "Choose identities and a resource";
      byID("revision").textContent = `Policy revision ${revision}`;
      message("Each selector shows up to 50 records. Choose the exact certificates to inspect.");
    } catch {
      if (attempt !== generation) return;
      clear(); reset();
      message("Policy choices could not be verified. Refresh to check your access and start a new snapshot.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) { pending = undefined; inventory.setAttribute("aria-busy", "false"); }
    }
  }
  function renderAccess(pages) {
    const form = element("form", undefined, "access-form");
    form.setAttribute("aria-label", "Inspect effective access");
    for (const [key, type] of Object.entries(choiceTypes)) {
      const page = pages[key], state = choices[key];
      const field = element("div", undefined, "access-choice");
      const label = element("label", type.label); label.htmlFor = `access-${key}`;
      const select = element("select"); select.id = label.htmlFor; select.required = true;
      const empty = element("option", page.Items.length ? `Choose ${type.label.toLowerCase()}` : "No records on this page"); empty.value = ""; select.append(empty);
      for (const item of page.Items) {
        const title = key === "resource" ? `${item.Name} · revision ${item.Revision} · ${item.Address}:${item.Port}` : `${item.PrincipalName} · ${item.Fingerprint.slice(0, 12)}${item.Revoked ? " · revoked" : ""}`;
        const option = element("option", title); option.value = item.ID; select.append(option);
      }
      select.value = page.Items.some((item) => item.ID === state.selected) ? state.selected : "";
      state.selected = select.value;
      const detail = element("p", "", "record-id");
      function selected(event) {
        state.selected = select.value;
        const item = page.Items.find((item) => item.ID === select.value);
        detail.textContent = item ? (key === "resource" ? `${item.Protocol.toUpperCase()} · ${item.ConnectorID}` : `SHA-256 ${item.Fingerprint}`) : "";
        const prior = byID("access-result");
        prior?.replaceChildren(); prior?.removeAttribute("data-allowed");
        if (event) {
          byID("page-summary").textContent = "Selection has not been checked";
          message("Selection changed. Check effective access to verify this combination.");
        }
      }
      select.addEventListener("change", selected); selected();
      const pager = element("div", undefined, "choice-pagination");
      const previous = element("button", "Previous"); previous.type = "button"; previous.disabled = state.index === 0; previous.setAttribute("aria-label", `Previous ${type.label.toLowerCase()} page`);
      const next = element("button", "Next"); next.type = "button"; next.disabled = !page.Next; next.setAttribute("aria-label", `Next ${type.label.toLowerCase()} page`);
      previous.addEventListener("click", () => { if (!pending && state.index > 0) { state.index--; state.selected = ""; void loadAccess(); } });
      next.addEventListener("click", () => { if (!pending && page.Next) { state.cursors = state.cursors.slice(0, state.index + 1); state.cursors.push(page.Next); state.index++; state.selected = ""; void loadAccess(); } });
      pager.append(previous, element("span", `Page ${state.index + 1}`), next);
      field.append(label, select, detail, pager); form.append(field);
    }
    const submit = element("button", "Check effective access", "primary-action"); submit.type = "submit"; form.append(submit);
    const result = element("div", undefined, "access-result"); result.id = "access-result";
    form.addEventListener("submit", (event) => { event.preventDefault(); if (!pending && form.reportValidity()) void inspectAccess(form, pages, result); });
    records.replaceChildren(form, result, element("p", "This is a policy snapshot. Opening a connection still requires fresh identity proofs and online authorization. Application login remains separate.", "access-explanation"));
  }
  async function inspectAccess(form, pages, target) {
    const resource = pages.resource.Items.find((item) => item.ID === choices.resource.selected);
    const device = pages.device.Items.find((item) => item.ID === choices.device.selected);
    const connector = pages.connector.Items.find((item) => item.ID === choices.connector.selected);
    if (!resource || !device || !connector) return;
    cancel();
    const attempt = generation;
    const request = { DeviceCertificateID: choices.device.selected, ConnectorCertificateID: choices.connector.selected, ResourceID: resource.ID, Revision: resource.Revision, PolicyRevision: revision };
    target.replaceChildren(); message("Checking effective access…"); inventory.setAttribute("aria-busy", "true");
    const controls = [...form.querySelectorAll("button, select")].map((node) => [node, node.disabled]);
    for (const [node] of controls) node.disabled = true;
    const controller = new AbortController(); pending = controller;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const data = await privateJSON("/api/v1/admin/dashboard/access", request, controller.signal);
      const allowedFields = ["Version", "Request", "PolicyRevision", "ObservedAt", "Allowed", "Reason", "UserID", "UserName", "DeviceID", "DeviceName", "ConnectorID", "Resource", "GrantID", "HostBindingID"];
      const reasons = { allowed_by_current_policy: "Allowed by current policy", device_identity_unavailable: "Device identity is unavailable", connector_identity_unavailable: "Connector identity is unavailable", no_unique_current_policy: "No unique current grant and hosting permission", session_capacity_unavailable: "Session capacity is unavailable" };
      if (!data || Object.keys(data).some((key) => !allowedFields.includes(key)) || data.Version !== 1 || data.PolicyRevision !== revision || typeof data.Allowed !== "boolean" || !Object.hasOwn(reasons, data.Reason) || typeof data.ObservedAt !== "string" || !Number.isFinite(Date.parse(data.ObservedAt)) ||
          !data.Request || Object.keys(data.Request).length !== Object.keys(request).length || Object.entries(request).some(([key, value]) => data.Request[key] !== value) ||
          ["UserID", "UserName", "DeviceID", "DeviceName", "ConnectorID", "GrantID", "HostBindingID"].some((key) => typeof data[key] !== "string" || data[key].length > 4096) || data.Allowed !== (data.Reason === "allowed_by_current_policy")) throw new Error("Invalid inspection");
      const resourceFields = ["ID", "Revision", "Name", "ConnectorID", "ConnectorName", "Address", "Protocol", "Port", "Until"];
      if (data.Allowed && (!data.Resource || Object.keys(data.Resource).length !== resourceFields.length || Object.keys(data.Resource).some((key) => !resourceFields.includes(key)) || data.DeviceID !== device.PrincipalID || data.ConnectorID !== connector.PrincipalID ||
          data.Resource.ID !== request.ResourceID || data.Resource.Revision !== request.Revision || data.Resource.ConnectorID !== data.ConnectorID || data.Resource.ConnectorID !== resource.ConnectorID || data.Resource.Address !== resource.Address || data.Resource.Port !== resource.Port || data.Resource.Name !== resource.Name || data.Resource.Protocol !== resource.Protocol || data.Resource.Protocol !== "tcp" || !Number.isSafeInteger(data.Resource.Port) || data.Resource.Port < 1 || data.Resource.Port > 65535 ||
          ["Name", "ConnectorName", "Address", "Until"].some((key) => typeof data.Resource[key] !== "string" || data.Resource[key].length > 4096) || !Number.isFinite(Date.parse(data.Resource.Until)))) throw new Error("Invalid destination");
      if (!data.Allowed && data.Resource) throw new Error("Denied result includes permission");
      if (attempt !== generation) return;
      target.append(element("h2", reasons[data.Reason]));
      target.dataset.allowed = String(data.Allowed);
      if (data.Allowed) {
        const fields = [["Identity", `${data.UserName} / ${data.DeviceName}`], ["Resource", `${data.Resource.Name} · revision ${data.Resource.Revision}`], ["Destination", `${data.Resource.Address}:${data.Resource.Port} / TCP`], ["Connector", data.Resource.ConnectorName], ["Until", new Date(data.Resource.Until).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC")]];
        const details = element("dl");
        for (const [label, value] of fields) details.append(element("dt", label), element("dd", value));
        target.append(details, element("p", "This covers only the displayed resource revision and destination. Other ports and LAN devices require their own explicit grants."));
      } else target.append(element("p", "The selected identities cannot currently open this resource. Review identity status, the resource revision, the device grant and connector hosting permission."));
      target.append(element("p", `Observed ${new Date(data.ObservedAt).toISOString()} · policy revision ${data.PolicyRevision}`, "record-id"));
      byID("page-summary").textContent = "Policy snapshot checked";
      message(reasons[data.Reason]);
    } catch {
      if (attempt !== generation) return;
      clear(); reset();
      message("Effective access could not be verified. Refresh to start a new snapshot; no permission has been created.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) { pending = undefined; inventory.setAttribute("aria-busy", "false"); for (const [node, disabled] of controls) node.disabled = disabled; }
    }
  }
  const policyTitles = { "create-resource": "Create resource", "revise-resource": "Revise resource", grant: "Add device grant", host: "Add hosting permission" };
  for (const entity of Object.values(lifecycleEntities)) for (const [action, label] of [["create", "Add"], ["rename", "Rename"], ["disable", "Revoke"]]) policyTitles[`${action}-${entity}`] = `${label} ${entity}${action === "disable" ? " access" : ""}`;
  policyTitles.invite = "Create enrollment invitation"; policyTitles["revoke-enrollment"] = "Revoke enrollment";
  const policyTypes = { connector: "connectors", device: "devices", resource: "resources", user: "users", issuer: "issuers" };
  const uuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== "00000000-0000-0000-0000-000000000000";
  const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  const date = (value) => typeof value === "string" && value.length < 64 && Number.isFinite(Date.parse(value));
  function startPolicy(kind, previous) {
    if (pending || document.hidden) return;
    const [action, entity] = kind.split("-");
    if (Object.values(lifecycleEntities).includes(entity)) {
      const keys = kind === "create-device" ? ["user"] : [];
      policy = { kind, previous, revision, lifecycle: { action, entity }, fields: { Name: previous?.Name || "", Platform: "linux", NotAfter: "" }, choices: Object.fromEntries(keys.map((key) => [key, { cursors: [""], index: 0, selected: "" }])) };
      void loadPolicy(policy); return;
    }
    const keys = kind.endsWith("resource") ? ["connector"] : kind === "grant" ? ["device", "resource"] : ["resource"];
    policy = { kind, previous, revision, fields: { Name: previous?.Name || "", Address: previous?.Address || "", Port: String(previous?.Port || ""), From: "", Until: "" }, choices: Object.fromEntries(keys.map((key) => [key, { cursors: [""], index: 0, selected: key === "connector" ? previous?.ConnectorID || "" : "" }])) };
    void loadPolicy(policy);
  }
  function policyCancel() {
    reset(); document.querySelector(".pagination").hidden = false; void load();
  }
  async function loadPolicy(state) {
    cancel(); const attempt = generation;
    records.replaceChildren(); document.querySelector(".pagination").hidden = true;
    inventory.setAttribute("aria-busy", "true"); message("Loading current choices for this change…");
    const controller = new AbortController(); pending = controller;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const pages = {};
      // Each subsequent selector is bound to the first verified policy revision.
      for (const [key, choice] of Object.entries(state.choices)) {
        const request = { Section: policyTypes[key], After: choice.cursors[choice.index], Limit: 50, PolicyRevision: state.revision };
        if (key === "issuer") request.Profile = state.profile;
        const page = await privateJSON("/api/v1/admin/dashboard/inventory", request, controller.signal);
        if (!validPage(page, policyTypes[key], state.revision)) throw new Error("Invalid policy choices");
        state.revision = page.PolicyRevision; pages[key] = page;
      }
      if (attempt !== generation || state !== policy || document.hidden) return;
      renderPolicy(state, pages);
      byID("page-summary").textContent = policyTitles[state.kind];
      message("Choose the exact destination and scope. Review the preview before approving with a security key.");
    } catch {
      if (attempt !== generation) return;
      clear(); reset(); message("Choices could not be verified. Refresh to start again.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) { pending = undefined; inventory.setAttribute("aria-busy", "false"); }
    }
  }
  function renderPolicy(state, pages) {
    const form = element("form", undefined, "access-form policy-form");
    form.setAttribute("aria-label", policyTitles[state.kind]); form.autocomplete = "off";
    for (const [key, choice] of Object.entries(state.choices)) {
      const page = pages[key], field = element("div", undefined, "access-choice");
      const label = element("label", key[0].toUpperCase() + key.slice(1)); label.htmlFor = `policy-${key}`;
      const select = element("select"); select.id = label.htmlFor; select.required = true;
      const empty = element("option", `Choose ${key}`); empty.value = ""; select.append(empty);
      for (const item of page.Items.filter((item) => item.Enabled)) {
        const title = key === "issuer" ? `${item.Profile} · ${item.ID}` : key === "resource" ? `${item.Name} · revision ${item.Revision} · ${item.Address}:${item.Port}` : `${item.Name} · ${item.ID}`;
        const option = element("option", title); option.value = item.ID; select.append(option);
      }
      select.value = choice.selected; choice.selected = select.value;
      select.addEventListener("change", () => { choice.selected = select.value; });
      const pager = element("div", undefined, "choice-pagination");
      for (const forward of [false, true]) {
        const button = element("button", forward ? "Next" : "Previous"); button.type = "button";
        button.disabled = forward ? !page.Next : choice.index === 0;
        button.setAttribute("aria-label", `${forward ? "Next" : "Previous"} ${key} choices`);
        button.addEventListener("click", () => {
          if (pending || state !== policy) return;
          if (forward) { choice.cursors = choice.cursors.slice(0, choice.index + 1); choice.cursors.push(page.Next); choice.index++; }
          else choice.index--;
          choice.selected = ""; void loadPolicy(state);
        }); pager.append(button);
      }
      field.append(label, select, element("p", `Page ${choice.index + 1} · up to 50 records`, "record-id"), pager); form.append(field);
    }
    let fields = state.kind.endsWith("resource") ? [["Name", "Resource name", "text"], ["Address", "Canonical destination IP address", "text"], ["Port", "TCP port", "number"]] : [["From", "Valid from (UTC)", "datetime-local"], ["Until", "Valid until (UTC)", "datetime-local"]];
    if (state.invitation) {
      fields = state.previous ? [] : [["ExpiresAt", "Invitation expires (UTC, within one hour)", "datetime-local"], ["NotAfter", "Issued identity expires (UTC)", "datetime-local"]];
      if (state.previous) form.append(element("p", `Enrollment ${state.previous.ID} · ${state.previous.Profile} · ${state.previous.State}`, "record-id"));
    }
    if (state.lifecycle) {
      fields = state.lifecycle.action === "disable" ? [] : [["Name", `${state.lifecycle.entity[0].toUpperCase() + state.lifecycle.entity.slice(1)} name`, "text"]];
      if (state.previous) form.append(element("p", `${state.previous.Name} · ${state.previous.ID}`, "record-id"));
      if (state.kind === "create-device") {
        fields.push(["NotAfter", "Device authorization expires (UTC)", "datetime-local"]);
        const field = element("div", undefined, "access-choice"), label = element("label", "Platform"), select = element("select");
        label.htmlFor = "policy-platform"; select.id = label.htmlFor;
        for (const value of ["linux", "windows", "android"]) { const option = element("option", value); option.value = value; select.append(option); }
        select.value = state.fields.Platform; select.addEventListener("change", () => { state.fields.Platform = select.value; });
        field.append(label, select); form.append(field);
      }
    }
    for (const [key, title, type] of fields) {
      const field = element("div", undefined, "access-choice"), label = element("label", title), input = element("input");
      label.htmlFor = `policy-${key.toLowerCase()}`; input.id = label.htmlFor; input.type = type; input.required = true; input.value = state.fields[key];
      if (type === "text") { input.maxLength = key === "Name" ? 128 : 45; input.spellcheck = false; }
      if (type === "number") { input.min = "1"; input.max = "65535"; input.step = "1"; }
      if (type === "datetime-local") { input.min = "2000-01-01T00:00"; input.max = "2261-12-31T23:59"; }
      input.addEventListener("input", () => { state.fields[key] = input.value; }); field.append(label, input); form.append(field);
    }
    const submit = element("button", "Review change", "primary-action"); submit.type = "submit";
    const cancelButton = element("button", "Cancel change"); cancelButton.type = "button"; cancelButton.addEventListener("click", policyCancel);
    form.append(submit, cancelButton);
    form.addEventListener("submit", (event) => { event.preventDefault(); if (!pending && state === policy && form.reportValidity()) void previewPolicy(state, pages, form); });
    const explanation = state.invitation ? invitationEffect(state) : state.lifecycle ? lifecycleEffect(state) : state.kind.endsWith("resource") ? "A resource defines one TCP destination. Device grants and connector hosting permissions must explicitly cover its revision." : "Enter both times in UTC. The displayed device and exact resource revision define the permission.";
    records.replaceChildren(form, element("p", explanation, "access-explanation"));
  }
  function policyDraft(state, pages) {
    if (state.invitation) {
      if (state.previous) return { Kind: state.kind, EnrollmentID: state.previous.ID, PolicyRevision: state.revision };
      const principal = pages[state.profile].Items.find((item) => item.ID === state.choices[state.profile].selected && item.Enabled);
      const issuer = pages.issuer.Items.find((item) => item.ID === state.choices.issuer.selected && item.Enabled && item.Profile === state.profile);
      if (!principal || !issuer || Date.parse(issuer.NotAfter) <= Date.now()) throw new Error("Invalid invitation identity");
      return { Kind: state.kind, PrincipalID: principal.ID, IssuerID: issuer.ID, Profile: state.profile, PolicyRevision: state.revision, ExpiresAt: new Date(state.fields.ExpiresAt + "Z").toISOString(), NotAfter: new Date(state.fields.NotAfter + "Z").toISOString() };
    }
    if (state.lifecycle) {
      const draft = { Kind: state.kind, PolicyRevision: state.revision };
      if (state.previous) draft.TargetID = state.previous.ID;
      if (state.lifecycle.action !== "disable") draft.Name = state.fields.Name;
      if (state.kind === "create-device") {
        const user = pages.user.Items.find((item) => item.ID === state.choices.user.selected && item.Enabled);
        if (!user) throw new Error("Missing device owner");
        draft.UserID = user.ID; draft.Platform = state.fields.Platform; draft.NotAfter = new Date(state.fields.NotAfter + "Z").toISOString();
      }
      return { Lifecycle: draft };
    }
    if (state.kind.endsWith("resource")) {
      const connector = pages.connector.Items.find((item) => item.ID === state.choices.connector.selected && item.Enabled);
      if (!connector) throw new Error("Missing connector");
      const draft = { Resource: { Name: state.fields.Name, ConnectorID: connector.ID, Address: state.fields.Address, Port: Number(state.fields.Port), Protocol: "tcp" } };
      if (state.previous) { draft.ResourceID = state.previous.ID; draft.ExpectedRevision = state.previous.Revision; }
      return draft;
    }
    const resource = pages.resource.Items.find((item) => item.ID === state.choices.resource.selected && item.Enabled);
    if (!resource) throw new Error("Missing resource");
    const permission = { ResourceID: resource.ID, Revision: resource.Revision, From: new Date(state.fields.From + "Z").toISOString(), Until: new Date(state.fields.Until + "Z").toISOString() };
    if (Date.parse(permission.Until) <= Date.parse(permission.From)) throw new Error("Invalid interval");
    if (state.kind === "host") return { Hosting: { ...permission, ConnectorID: resource.ConnectorID } };
    const device = pages.device.Items.find((item) => item.ID === state.choices.device.selected && item.Enabled);
    if (!device) throw new Error("Missing device");
    return { Grant: { ...permission, UserID: device.UserID, DeviceID: device.ID } };
  }
  function validPolicyPreview(view, draft, state, pages) {
    if (state.lifecycle) return validLifecyclePreview(view, draft.Lifecycle, state, pages);
    const fields = ["ID", "Digest", "Kind", "UserID", "UserName", "DeviceID", "DeviceName", "Resource", "From", "Until", "ExpiresAt", "PolicyRevision"];
    if (state.previous) fields.push("Previous");
    if (!exact(view, fields) || !uuid(view.ID) || !/^[0-9a-f]{64}$/.test(view.Digest) || view.Kind !== state.kind || view.PolicyRevision !== state.revision || !date(view.ExpiresAt) || Date.parse(view.ExpiresAt) <= Date.now() || Date.parse(view.ExpiresAt) > Date.now() + 301000 || !date(view.From) || !date(view.Until)) return false;
    if (["UserID", "UserName", "DeviceID", "DeviceName"].some((key) => typeof view[key] !== "string" || view[key].length > 4096)) return false;
    const resourceFields = ["ID", "Revision", "Name", "ConnectorID", "ConnectorName", "Address", "Port", "Protocol", "Until"];
    function resourceMatches(actual, expected, connectorName) {
      return exact(actual, resourceFields) && uuid(actual.ID) && Number.isSafeInteger(actual.Revision) && actual.Revision > 0 && actual.Protocol === "tcp" && date(actual.Until) && typeof actual.ConnectorName === "string" && actual.ConnectorName.length <= 4096 && (connectorName === undefined || actual.ConnectorName === connectorName) && Object.entries(expected).every(([key, value]) => actual[key] === value);
    }
    if (draft.Resource) {
      const connector = pages.connector.Items.find((item) => item.ID === draft.Resource.ConnectorID);
      const expected = { ...draft.Resource, Revision: state.previous ? state.previous.Revision + 1 : 1 };
      if (state.previous) expected.ID = state.previous.ID;
      if (!resourceMatches(view.Resource, expected, connector.Name)) return false;
      if (state.previous && !resourceMatches(view.Previous, Object.fromEntries(["ID", "Revision", "Name", "ConnectorID", "Address", "Port", "Protocol"].map((key) => [key, state.previous[key]])))) return false;
      return view.UserID === "" && view.DeviceID === "" && view.UserName === "" && view.DeviceName === "";
    }
    const permission = draft.Grant || draft.Hosting, resource = pages.resource.Items.find((item) => item.ID === permission.ResourceID);
    if (!resourceMatches(view.Resource, Object.fromEntries(["ID", "Revision", "Name", "ConnectorID", "Address", "Port", "Protocol"].map((key) => [key, resource[key]]))) || Date.parse(view.From) !== Date.parse(permission.From) || Date.parse(view.Until) !== Date.parse(permission.Until)) return false;
    if (!draft.Grant) return view.UserID === "" && view.DeviceID === "" && view.UserName === "" && view.DeviceName === "";
    const device = pages.device.Items.find((item) => item.ID === permission.DeviceID);
    return view.UserID === permission.UserID && view.DeviceID === permission.DeviceID && view.DeviceName === device.Name && view.UserName.length > 0;
  }
  async function previewPolicy(state, pages, form) {
    cancel(); const attempt = generation, controller = new AbortController(); pending = controller;
    inventory.setAttribute("aria-busy", "true"); message("Preparing an exact preview…");
    for (const node of form.querySelectorAll("input, select, button")) node.disabled = true;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const draft = policyDraft(state, pages);
      const view = await privateJSON(state.invitation ? "/api/v1/admin/invitations/challenge" : "/api/v1/admin/policy/preview", draft, controller.signal);
      if (!(state.invitation ? validInvitationPreview(view, draft, state, pages) : validPolicyPreview(view, draft, state, pages))) throw new Error("Preview differs from draft");
      if (attempt !== generation || state !== policy || document.hidden) return;
      if (state.invitation) renderInvitationPreview(view, state); else renderPolicyPreview(view, state);
      message("Review every detail. This change has not been applied.");
    } catch {
      if (attempt !== generation) return;
      clear(); reset(); message("The preview could not be verified. No approval was submitted. Refresh and check the destination, dates and current policy.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) { pending = undefined; inventory.setAttribute("aria-busy", "false"); }
    }
  }
  function renderPolicyPreview(view, state) {
    if (state.lifecycle) { renderLifecyclePreview(view, state); return; }
    const panel = element("section", undefined, "access-result policy-preview"); panel.id = "policy-preview";
    const heading = element("h2", `Review: ${policyTitles[state.kind]}`); heading.tabIndex = -1; panel.append(heading);
    function details(resource, title) {
      panel.append(element("h3", title)); const list = element("dl");
      for (const [label, value] of [["Resource", resource.Name], ["Resource ID", resource.ID], ["Revision", resource.Revision], ["Destination", `${resource.Address}:${resource.Port} / TCP`], ["Connector", resource.ConnectorName], ["Connector ID", resource.ConnectorID]]) list.append(element("dt", label), element("dd", String(value)));
      panel.append(list);
    }
    if (view.Previous) details(view.Previous, "Current destination");
    details(view.Resource, view.Previous ? "Proposed destination" : "Destination");
    const scope = element("dl");
    if (state.kind === "grant") for (const [label, value] of [["Person", view.UserName], ["User ID", view.UserID], ["Device", view.DeviceName], ["Device ID", view.DeviceID]]) scope.append(element("dt", label), element("dd", value));
    if (state.kind === "grant" || state.kind === "host") for (const [label, value] of [["From (UTC)", view.From], ["Until (UTC)", view.Until]]) scope.append(element("dt", label), element("dd", new Date(value).toISOString()));
    panel.append(scope, element("p", `Approval expires ${new Date(view.ExpiresAt).toISOString()} · policy revision ${view.PolicyRevision}`));
    if (view.Previous) panel.append(element("p", "Existing grants and hosting permissions remain bound to the previous revision. The new revision needs its own permissions."));
    const approve = element("button", "Approve with security key", "primary-action"); approve.type = "button";
    const cancelButton = element("button", "Cancel change"); cancelButton.type = "button"; cancelButton.addEventListener("click", policyCancel);
    const actions = element("div", undefined, "policy-actions"); actions.append(approve, cancelButton); panel.append(actions);
    approve.addEventListener("click", () => { if (!pending && state === policy && !document.hidden) void approvePolicy(view, state, panel, approve); });
    records.replaceChildren(panel); heading.focus();
  }
  async function approvePolicy(view, state, panel, button) {
    cancel(); const attempt = generation, controller = new AbortController(); pending = controller;
    button.disabled = true; let submitted = false;
    const timeout = setTimeout(() => controller.abort(), Math.max(1, Math.min(60000, Date.parse(view.ExpiresAt) - Date.now())));
    const active = () => attempt === generation && state === policy && !document.hidden && !controller.signal.aborted && Date.now() < Date.parse(view.ExpiresAt);
    try {
      if (!active() || !globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON || !PublicKeyCredential.prototype.toJSON) throw new Error("WebAuthn unavailable");
      message("Use a registered security key and complete its user verification.");
      const challenge = await privateJSON("/api/v1/admin/policy/challenge", { ID: view.ID, Digest: view.Digest }, controller.signal);
      if (!active()) return;
      const options = challenge?.Approval?.publicKey;
      if (!exact(challenge, ["ID", "Approval"]) || !uuid(challenge.ID) || !options || options.rpId !== location.hostname || options.userVerification !== "required" || !Array.isArray(options.allowCredentials) || options.allowCredentials.length < 1) throw new Error("Invalid approval challenge");
      const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options), signal: controller.signal });
      if (!active()) return;
      if (!credential || credential.type !== "public-key") throw new Error("No security key assertion");
      submitted = true;
      message("Submitting the approved change…");
      const result = await privateJSON("/api/v1/admin/policy/confirm", { ID: challenge.ID, Response: credential.toJSON() }, controller.signal);
      if (attempt !== generation || state !== policy || document.hidden) return;
      if (!exact(result, [])) throw new Error("Invalid confirmation");
      panel.replaceChildren(element("h2", "Change applied"), element("p", "Refresh the inventory to see the current configuration and inspect effective access."));
      const refresh = element("button", "Return to inventory", "primary-action"); refresh.type = "button"; refresh.addEventListener("click", policyCancel); panel.append(refresh);
      message("The server confirmed that this change was applied.");
    } catch {
      if (attempt !== generation) return;
      message(submitted ? "The result could not be confirmed. The change may have been applied. Refresh and inspect the inventory before creating another change." : "Approval was not submitted. The key, browser, access or policy could not be verified. Cancel this change and start a fresh preview.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) pending = undefined;
    }
  }
  const factorTitles = { "bootstrap-factor": "Initial key registration", "register-factor": "Add security key", "test-factor": "Test security key", "disable-factor": "Retire security key" };
  function startFactor(kind, item) {
    if (pending || document.hidden || !revision) return;
    cancel(); policy = null;
    const state = { kind, item, revision, factorID: item?.ID || "", userID: "", expires: 0, registration: null };
    factor = state;
    document.querySelector(".pagination").hidden = true;
    const panel = element("section", undefined, "access-result policy-preview"); panel.id = "factor-preview";
    const heading = element("h2", factorTitles[kind]); heading.tabIndex = -1; panel.append(heading);
    if (item) {
      const details = element("dl");
      for (const [label, value] of [["Key record", item.ID], ["Attested model", item.ModelID], ["Key test", item.Tested ? "Test recorded" : "Needs key test"]]) details.append(element("dt", label), element("dd", value));
      panel.append(details);
    }
    const explanation = {
      "bootstrap-factor": "Initial registration is available only during the server's local registration window and for its first two key records. Register each physical key separately, then test it. This step does not complete deployment bootstrap or recovery setup.",
      "register-factor": "First approve with a tested registered key. Then switch to the new key for registration. Test the new key afterward before relying on it for administration or recovery.",
      "test-factor": "Connect the exact key shown above and complete its user verification. A successful test records that this credential worked now.",
      "disable-factor": "Approve with a different tested key. The selected key will lose administrator authority. Keep the approving backup key available; a retired key cannot be used to authorize its own replacement."
    };
    panel.append(element("p", explanation[kind]), element("p", `Policy revision ${state.revision}`));
    const label = kind === "bootstrap-factor" ? "Register initial key" : kind === "test-factor" ? "Test this key" : kind === "disable-factor" ? "Approve retirement with backup key" : "Approve adding a key";
    factorButtons(state, panel, label);
    records.replaceChildren(panel); heading.focus(); message("Review the key operation before continuing.");
  }
  function factorButtons(state, panel, label) {
    const actions = element("div", undefined, "policy-actions"), button = element("button", label, "primary-action"), cancelButton = element("button", "Cancel key operation");
    button.type = cancelButton.type = "button";
    button.addEventListener("click", () => { if (!pending && state === factor && !document.hidden) void performFactor(state, panel, button); });
    cancelButton.addEventListener("click", policyCancel);
    actions.append(button, cancelButton); panel.append(actions);
  }
  function validFactorCeremony(challenge, registration, state) {
    if (!exact(challenge, ["ID", registration ? "Registration" : "Approval"]) || !uuid(challenge.ID)) return false;
    const options = (registration ? challenge.Registration : challenge.Approval)?.publicKey;
    if (!options || typeof options.challenge !== "string" || options.challenge.length < 16 || options.challenge.length > 1024) return false;
    if (!registration) return options.rpId === location.hostname && options.userVerification === "required" && Array.isArray(options.allowCredentials) && options.allowCredentials.length > 0 && (state.kind !== "test-factor" || options.allowCredentials.length === 1);
    const handle = btoa(state.userID).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return options.rp?.id === location.hostname && options.user?.id === handle && options.attestation === "direct" && options.authenticatorSelection?.authenticatorAttachment === "cross-platform" && options.authenticatorSelection?.userVerification === "required";
  }
  async function performFactor(state, panel, button) {
    cancel(); const attempt = generation, controller = new AbortController(); pending = controller;
    button.disabled = true; let submitted = false;
    const timeout = setTimeout(() => controller.abort(), 60000);
    const active = () => attempt === generation && state === factor && !document.hidden && !controller.signal.aborted && (!state.expires || Date.now() < state.expires);
    try {
      if (!active() || !globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON || !PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.prototype.toJSON) throw new Error("WebAuthn unavailable");
      let challenge = state.registration;
      const registering = !!challenge || state.kind === "bootstrap-factor";
      if (!challenge) {
        message("Checking the administrator identity and current key policy…");
        const security = await privateJSON("/api/v1/admin/dashboard/inventory", { Section: "security", Limit: 1, PolicyRevision: state.revision }, controller.signal);
        if (!active()) return;
        if (!validPage(security, "security", state.revision) || !uuid(security.Items[0].ID)) throw new Error("Invalid administrator identity");
        state.userID = security.Items[0].ID;
        const request = { Kind: state.kind, FactorID: state.factorID, PolicyRevision: state.revision };
        const result = await privateJSON("/api/v1/admin/factors/challenge", request, controller.signal);
        if (!active()) return;
        if (!exact(result, ["Kind", "FactorID", "PolicyRevision", "ExpiresAt", "Challenge"]) || result.Kind !== state.kind || result.PolicyRevision !== state.revision || !uuid(result.FactorID) || (request.FactorID && result.FactorID !== request.FactorID) || !date(result.ExpiresAt) || Date.parse(result.ExpiresAt) <= Date.now() || Date.parse(result.ExpiresAt) > Date.now() + 121000) throw new Error("Changed key operation");
        state.factorID = result.FactorID; state.expires = Date.parse(result.ExpiresAt); challenge = result.Challenge;
      }
      if (!validFactorCeremony(challenge, registering, state)) throw new Error("Invalid key ceremony");
      message(registering ? "Connect the new key and complete registration and user verification." : state.kind === "disable-factor" ? "Use a different tested key to approve retirement." : "Use the selected registered key and complete its user verification.");
      const options = (registering ? challenge.Registration : challenge.Approval).publicKey;
      const credential = registering
        ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options), signal: controller.signal })
        : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options), signal: controller.signal });
      if (!active()) return;
      if (!credential || credential.type !== "public-key") throw new Error("No key response");
      submitted = true; message("Submitting the security-key response…");
      const result = await privateJSON("/api/v1/admin/factors/confirm", { ID: challenge.ID, Response: credential.toJSON() }, controller.signal);
      if (attempt !== generation || state !== factor || document.hidden) return;
      if (state.kind === "register-factor" && !registering) {
        if (!exact(result, ["Registration"]) || !validFactorCeremony(result.Registration, true, state)) throw new Error("Invalid registration confirmation");
        state.registration = result.Registration;
        panel.replaceChildren(element("h2", "Connect the new security key"), element("p", "Adding a key was approved. Switch from the approving key to the new key, then register it. The new key is not registered or tested yet."), element("p", `New key record ${state.factorID} · finish before ${new Date(state.expires).toISOString()}`));
        factorButtons(state, panel, "Register new key");
        message("Approval confirmed. Register the new key before the operation expires.");
      } else {
        if (!exact(result, [])) throw new Error("Invalid key confirmation");
        const title = registering ? "Security key registered" : state.kind === "test-factor" ? "Security key test passed" : "Security key retired";
        panel.replaceChildren(element("h2", title), element("p", registering ? "The server accepted this registration. Return to the key list and test this key separately before relying on it." : "The server confirmed this key operation. Refresh the key list to check the current configuration."), element("p", `Key record ${state.factorID}`, "record-id"));
        const back = element("button", "Return to security keys", "primary-action"); back.type = "button"; back.addEventListener("click", policyCancel); panel.append(back);
        message(title + ".");
      }
      const heading = panel.querySelector("h2"); heading.tabIndex = -1; heading.focus();
    } catch {
      if (attempt !== generation) return;
      message(submitted ? "The result could not be confirmed. The key operation may have been applied. Refresh and inspect the key records before starting another operation." : "No key response was submitted. The key, browser, access or policy could not be verified. Cancel and begin a fresh operation.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) pending = undefined;
    }
  }
  function startInvitation(profile, previous) {
    if (pending || document.hidden || !["device", "connector"].includes(profile)) return;
    const keys = previous ? [] : ["issuer", profile];
    policy = { kind: previous ? "revoke-enrollment" : "invite", invitation: true, profile, previous, revision, fields: { ExpiresAt: "", NotAfter: "" }, choices: Object.fromEntries(keys.map((key) => [key, { cursors: [""], index: 0, selected: "" }])) };
    void loadPolicy(policy);
  }
  function invitationEffect(state) {
    return state.previous ? "This revokes the enrollment and any certificate issued through it. Dependent sessions are cancelled and new authentication is denied. The record is retained. Your current administrator device and management connectors are protected." : "The selected identity can enroll once with its own new key. The secret is created only after security-key approval and is shown once. It does not grant access to resources. Invitation expiry must be within one hour; identity expiry must fit the device and issuer authority.";
  }
  function validInvitationPreview(view, draft, state, pages) {
    if (!exact(view, ["Kind", "PolicyRevision", "ExpiresAt", "Invitation", "Challenge"]) || view.Kind !== state.kind || view.PolicyRevision !== state.revision || !date(view.ExpiresAt) || Date.parse(view.ExpiresAt) <= Date.now() || Date.parse(view.ExpiresAt) > Date.now() + 121000 || !validFactorCeremony(view.Challenge, false, state)) return false;
    const item = view.Invitation;
    if (!exact(item, ["ID", "IssuerID", "PrincipalID", "Profile", "ExpiresAt", "NotAfter", "PrincipalName", "UserID", "UserName", "State"]) || !uuid(item.ID) || !uuid(item.IssuerID) || !uuid(item.PrincipalID) || item.Profile !== state.profile || !date(item.ExpiresAt) || !date(item.NotAfter) || typeof item.PrincipalName !== "string" || !item.PrincipalName || item.PrincipalName.length > 4096 || typeof item.UserName !== "string" || item.UserName.length > 4096) return false;
    if (state.profile === "device" ? !uuid(item.UserID) || !item.UserName : item.UserID !== "" || item.UserName !== "") return false;
    const expected = state.previous || draft;
    if (item.IssuerID !== expected.IssuerID || item.PrincipalID !== expected.PrincipalID || Date.parse(item.ExpiresAt) !== Date.parse(expected.ExpiresAt) || Date.parse(item.NotAfter) !== Date.parse(expected.NotAfter)) return false;
    if (state.previous) return item.ID === expected.ID && item.State === expected.State && item.State !== "revoked";
    const principal = pages[state.profile].Items.find((record) => record.ID === draft.PrincipalID);
    return item.State === "pending-approval" && item.PrincipalName === principal.Name && (state.profile !== "device" || item.UserID === principal.UserID);
  }
  function renderInvitationPreview(view, state) {
    const item = view.Invitation, panel = element("section", undefined, "access-result policy-preview"); panel.id = "invitation-preview";
    const heading = element("h2", `Review: ${policyTitles[state.kind]}`); heading.tabIndex = -1;
    const list = element("dl"), values = [["Enrollment ID", item.ID], ["Profile", item.Profile], ["Identity", item.PrincipalName], ["Identity ID", item.PrincipalID], ["Issuer ID", item.IssuerID], ["State", item.State], ["Invitation expires (UTC)", new Date(item.ExpiresAt).toISOString()], ["Issued identity expires (UTC)", new Date(item.NotAfter).toISOString()]];
    if (item.UserID) values.push(["Owner", item.UserName], ["Owner ID", item.UserID]);
    for (const [label, value] of values) list.append(element("dt", label), element("dd", value));
    panel.append(heading, list, element("p", invitationEffect(state)), element("p", `Approval expires ${new Date(view.ExpiresAt).toISOString()} · policy revision ${view.PolicyRevision}`));
    const button = element("button", "Approve with security key", "primary-action"), back = element("button", "Cancel change"), actions = element("div", undefined, "policy-actions");
    button.type = back.type = "button"; back.addEventListener("click", policyCancel);
    button.addEventListener("click", () => { if (!pending && state === policy && !document.hidden) void approveInvitation(view, state, panel, button); });
    actions.append(button, back); panel.append(actions); records.replaceChildren(panel); heading.focus();
  }
  async function approveInvitation(view, state, panel, button) {
    cancel(); const attempt = generation, controller = new AbortController(); pending = controller;
    button.disabled = true; let submitted = false;
    const expires = Math.min(Date.parse(view.ExpiresAt), state.previous ? Infinity : Date.parse(view.Invitation.ExpiresAt));
    const timeout = setTimeout(() => controller.abort(), Math.max(1, Math.min(60000, expires - Date.now())));
    const active = () => attempt === generation && state === policy && !document.hidden && !controller.signal.aborted && Date.now() < expires;
    try {
      if (!active() || !globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON || !PublicKeyCredential.prototype.toJSON || !validFactorCeremony(view.Challenge, false, state)) throw new Error("Invalid invitation approval");
      message("Use a tested registered security key and complete its user verification.");
      const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(view.Challenge.Approval.publicKey), signal: controller.signal });
      if (!active()) return;
      if (!credential || credential.type !== "public-key") throw new Error("Missing security-key proof");
      submitted = true; message("Submitting the approved enrollment operation…");
      const result = await privateJSON("/api/v1/admin/invitations/confirm", { ID: view.Challenge.ID, Response: credential.toJSON() }, controller.signal);
      if (attempt !== generation || state !== policy || document.hidden) return;
      if (!active()) throw new Error("Confirmation expired");
      if (!exact(result, state.previous ? ["ID"] : ["ID", "Secret"]) || result.ID !== view.Invitation.ID || (!state.previous && (typeof result.Secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(result.Secret)))) throw new Error("Invalid enrollment confirmation");
      panel.replaceChildren(element("h2", state.previous ? "Enrollment revoked" : "Invitation created"), element("p", `Enrollment ${result.ID}`, "record-id"));
      if (!state.previous) {
        const label = element("label", "One-time invitation secret"), secret = element("input"), hide = element("button", "Hide secret now");
        secret.id = "invitation-secret"; label.htmlFor = secret.id; secret.type = "text"; secret.readOnly = true; secret.autocomplete = "off"; secret.spellcheck = false; secret.value = result.Secret;
        hide.type = "button";
        const clearSecret = () => { secret.value = ""; label.remove(); secret.remove(); hide.remove(); if (secretCleanup === clearSecret) secretCleanup = undefined; };
        secretCleanup = clearSecret;
        hide.addEventListener("click", clearSecret);
        panel.append(element("p", "Transfer this secret privately to the enrolling device. It cannot be retrieved again. It disappears here after one minute or when you leave this view."), label, secret, hide);
        setTimeout(clearSecret, Math.max(1, Math.min(60000, Date.parse(view.Invitation.ExpiresAt) - Date.now())));
      }
      const back = element("button", "Return to enrollments", "primary-action"); back.type = "button"; back.addEventListener("click", policyCancel); panel.append(back);
      const heading = panel.querySelector("h2"); heading.tabIndex = -1; heading.focus();
      message(state.previous ? "The server confirmed enrollment revocation." : "The server committed the invitation. Its secret is available only in this response.");
    } catch {
      if (attempt !== generation) return;
      message(submitted ? "The result could not be confirmed. The enrollment operation may have been applied. Refresh and inspect its status. If an invitation secret was lost, revoke that invitation before creating another." : "No approval was submitted. Cancel this operation and start a fresh review.", true);
    } finally {
      clearTimeout(timeout);
      if (attempt === generation) pending = undefined;
    }
  }
  function lifecycleEffect(state) {
    if (state.lifecycle.action === "create") return `This creates a ${state.lifecycle.entity} record. Enrollment, credentials and explicit access permissions are separate steps.`;
    if (state.lifecycle.action === "rename") return "Only the displayed name changes. The identity identifier and existing access remain the same.";
    const effects = { user: "All devices belonging to this user lose access. Dependent sessions are cancelled and new sessions are denied.", device: "This device loses access. Its dependent sessions are cancelled and new sessions are denied.", connector: "All resources delivered by this connector lose their transport. Dependent sessions are cancelled and new sessions are denied." };
    return effects[state.lifecycle.entity] + " The record remains as a disabled tombstone. Your current administrator user/device and connectors serving administrator resources are protected from this operation.";
  }
  function validLifecyclePreview(view, draft, state, pages) {
    const fields = ["ID", "Digest", "Kind", "UserID", "UserName", "DeviceID", "DeviceName", "Resource", "From", "Until", "ExpiresAt", "PolicyRevision", "Lifecycle"];
    if (state.lifecycle.action === "rename") fields.push("PreviousName");
    const zeroDate = (value) => date(value) && Date.parse(value) === Date.parse("0001-01-01T00:00:00Z");
    if (!exact(view, fields) || !uuid(view.ID) || !/^[0-9a-f]{64}$/.test(view.Digest) || view.Kind !== state.kind || view.Kind !== draft.Kind || view.PolicyRevision !== state.revision || !date(view.ExpiresAt) || Date.parse(view.ExpiresAt) <= Date.now() || Date.parse(view.ExpiresAt) > Date.now() + 301000 || !zeroDate(view.From) || !zeroDate(view.Until)) return false;
    if (["UserID", "UserName", "DeviceID", "DeviceName"].some((key) => view[key] !== "")) return false;
    const resource = view.Resource;
    if (!exact(resource, ["ID", "Revision", "Name", "ConnectorID", "ConnectorName", "Address", "Port", "Protocol", "Until"]) || resource.Revision !== 0 || resource.Port !== 0 || !zeroDate(resource.Until) || ["ID", "Name", "ConnectorID", "ConnectorName", "Address", "Protocol"].some((key) => resource[key] !== "")) return false;
    const target = view.Lifecycle, previous = state.previous;
    if (!exact(target, ["Entity", "ID", "Name", "UserID", "UserName", "Platform", "Version", "Enabled", "NotAfter"]) || target.Entity !== state.lifecycle.entity || !uuid(target.ID) || target.Enabled !== true || !date(target.NotAfter) || ["Name", "UserID", "UserName", "Platform", "Version"].some((key) => typeof target[key] !== "string" || target[key].length > 4096)) return false;
    if (previous && (target.ID !== previous.ID || draft.TargetID !== previous.ID)) return false;
    if (target.Name !== (state.lifecycle.action === "disable" ? previous.Name : draft.Name) || !target.Name) return false;
    if (state.lifecycle.action === "rename" && view.PreviousName !== previous.Name) return false;
    if (target.Entity === "device") {
      const expected = previous || { UserID: draft.UserID, Platform: draft.Platform, NotAfter: draft.NotAfter };
      if (!uuid(target.UserID) || !target.UserName || target.UserID !== expected.UserID || target.Platform !== expected.Platform || Date.parse(target.NotAfter) !== Date.parse(expected.NotAfter) || target.Version !== "") return false;
      if (!previous && target.UserName !== pages.user.Items.find((item) => item.ID === draft.UserID)?.Name) return false;
    } else if (target.UserID !== "" || target.UserName !== "" || target.Platform !== "" || !zeroDate(target.NotAfter)) return false;
    return target.Version === (target.Entity === "connector" ? previous?.Version || "unreported" : "");
  }
  function renderLifecyclePreview(view, state) {
    const target = view.Lifecycle, panel = element("section", undefined, "access-result policy-preview"); panel.id = "policy-preview";
    const heading = element("h2", `Review: ${policyTitles[state.kind]}`); heading.tabIndex = -1;
    const details = element("dl"), values = [["Record type", target.Entity], ["Record ID", target.ID]];
    if (view.PreviousName) values.push(["Current name", view.PreviousName], ["Proposed name", target.Name]);
    else values.push(["Name", target.Name]);
    if (target.Entity === "device") values.push(["Owner", target.UserName], ["Owner ID", target.UserID], ["Platform", target.Platform], ["Authorization expires (UTC)", new Date(target.NotAfter).toISOString()]);
    if (target.Entity === "connector") values.push(["Recorded version", target.Version]);
    for (const [label, value] of values) details.append(element("dt", label), element("dd", value));
    panel.append(heading, details, element("p", lifecycleEffect(state)), element("p", `Approval expires ${new Date(view.ExpiresAt).toISOString()} · policy revision ${view.PolicyRevision}`));
    const approve = element("button", "Approve with security key", "primary-action"), cancelButton = element("button", "Cancel change"), actions = element("div", undefined, "policy-actions");
    approve.type = cancelButton.type = "button";
    approve.addEventListener("click", () => { if (!pending && state === policy && !document.hidden) void approvePolicy(view, state, panel, approve); });
    cancelButton.addEventListener("click", policyCancel); actions.append(approve, cancelButton); panel.append(actions);
    records.replaceChildren(panel); heading.focus();
  }
  function select() {
    const candidate = location.hash.slice(1);
    if (candidate === "content") return;
    section = Object.hasOwn(sections, candidate) ? candidate : "users";
    for (const link of document.querySelectorAll("nav [data-section]")) {
      if (link.dataset.section === section || (link.dataset.section === "access" && accessViews.includes(section)) || (link.dataset.section === "security" && securityViews.includes(section))) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    byID("access-views").hidden = !accessViews.includes(section);
    byID("security-views").hidden = !securityViews.includes(section);
    for (const link of document.querySelectorAll("#access-views a, #security-views a")) {
      if (link.dataset.view === section) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    document.querySelector(".pagination").hidden = section === "access" || section === "security";
    byID("page-title").textContent = sections[section].title;
    byID("page-description").textContent = sections[section].description;
    byID("scope-title").textContent = sections[section].scopeTitle || "Configuration is only part of access.";
    byID("scope-description").textContent = sections[section].scopeDescription || "An enabled record still needs current grants, hosting permission, a valid identity and an online policy decision.";
    document.title = `Portico · ${sections[section].title}`;
    reset(); void load();
  }
  byID("refresh").addEventListener("click", () => { reset(); void load(); });
  nextButton.addEventListener("click", () => {
    if (pending || !next) return;
    cursors = cursors.slice(0, pageIndex + 1); cursors.push(next); pageIndex++; void load();
  });
  previousButton.addEventListener("click", () => { if (!pending && pageIndex > 0) { pageIndex--; void load(); } });
  window.addEventListener("hashchange", select);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { cancel(); clear(); reset(); message("Inventory hidden. It will be checked again when you return."); }
    else void load();
  });
  window.addEventListener("pagehide", () => { cancel(); clear(); reset(); });
  window.addEventListener("pageshow", (event) => { if (event.persisted) { reset(); void load(); } });
  select();
})();
