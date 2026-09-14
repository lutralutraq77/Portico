"use strict";

(() => {
  const sections = {
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
  const choiceTypes = {
    device: { label: "Device certificate", section: "certificates", profile: "device" },
    connector: { label: "Connector certificate", section: "certificates", profile: "connector" },
    resource: { label: "Resource", section: "resources", profile: "" }
  };
  let choices = {};
  let policy = null;

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
    policy = null;
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
    const hash = (value) => /^[0-9a-f]{64}$/.test(value);
    if (requestedSection === "security") return data.Items.length === 1 && data.Next === "" && data.Items.every((item) => hash(item.CertificateFingerprint) && item.TestedEnabledFactors <= item.EnabledFactors && Date.parse(item.CertificateExpiresAt) > Date.parse(data.ObservedAt));
    if (requestedSection === "audit") return (!data.Next || data.Next === data.Items.at(-1)?.ID) && data.Items.every((item, index) => item.Sequence > 0 && item.Generation > 0 && hash(item.Hash) && (item.Sequence === 1 ? item.PreviousHash === "" : hash(item.PreviousHash)) && (index === 0 || (item.Sequence === data.Items[index-1].Sequence + 1 && item.PreviousHash === data.Items[index-1].Hash)));
    return true;
  }
  function display(item, key) {
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
    if (section === "resources") { const cell = element("th", "Manage"); cell.scope = "col"; header.append(cell); }
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
      body.append(row);
    }
    table.append(body);
    const wrapper = element("div", undefined, "table-wrap"); wrapper.append(table);
    records.replaceChildren(wrapper);
    const actions = { resources: ["Create resource", "create-resource"], grants: ["Add device grant", "grant"], hosting: ["Add hosting permission", "host"] };
    if (Object.hasOwn(actions, section)) {
      const [label, kind] = actions[section], bar = element("div", undefined, "policy-actions");
      const button = element("button", label, "primary-action"); button.type = "button";
      button.addEventListener("click", () => startPolicy(kind)); bar.append(button); records.prepend(bar);
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
  const policyTypes = { connector: "connectors", device: "devices", resource: "resources" };
  const uuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== "00000000-0000-0000-0000-000000000000";
  const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  const date = (value) => typeof value === "string" && value.length < 64 && Number.isFinite(Date.parse(value));
  function startPolicy(kind, previous) {
    if (pending || document.hidden) return;
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
        const page = await privateJSON("/api/v1/admin/dashboard/inventory", { Section: policyTypes[key], After: choice.cursors[choice.index], Limit: 50, PolicyRevision: state.revision }, controller.signal);
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
        const title = key === "resource" ? `${item.Name} · revision ${item.Revision} · ${item.Address}:${item.Port}` : `${item.Name} · ${item.ID}`;
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
    const fields = state.kind.endsWith("resource") ? [["Name", "Resource name", "text"], ["Address", "Canonical destination IP address", "text"], ["Port", "TCP port", "number"]] : [["From", "Valid from (UTC)", "datetime-local"], ["Until", "Valid until (UTC)", "datetime-local"]];
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
    const explanation = state.kind.endsWith("resource") ? "A resource defines one TCP destination. Device grants and connector hosting permissions must explicitly cover its revision." : "Enter both times in UTC. The displayed device and exact resource revision define the permission.";
    records.replaceChildren(form, element("p", explanation, "access-explanation"));
  }
  function policyDraft(state, pages) {
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
      const view = await privateJSON("/api/v1/admin/policy/preview", draft, controller.signal);
      if (!validPolicyPreview(view, draft, state, pages)) throw new Error("Preview differs from draft");
      if (attempt !== generation || state !== policy || document.hidden) return;
      renderPolicyPreview(view, state);
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
  function select() {
    const candidate = location.hash.slice(1);
    if (candidate === "content") return;
    section = Object.hasOwn(sections, candidate) ? candidate : "users";
    for (const link of document.querySelectorAll("nav [data-section]")) {
      if (link.dataset.section === section || (link.dataset.section === "access" && accessViews.includes(section))) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    byID("access-views").hidden = !accessViews.includes(section);
    for (const link of document.querySelectorAll("#access-views a")) {
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
