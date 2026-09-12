"use strict";

(() => {
  const sections = {
    users: { title: "Users", description: "People registered in this deployment.", columns: [["Person", "Name", "ID"], ["Configuration", "Enabled"]], fields: { ID: "string", Name: "string", Enabled: "boolean" } },
    devices: { title: "Devices", description: "Registered devices and the identities they belong to.", columns: [["Device", "Name", "ID"], ["User", "UserID"], ["Platform", "Platform"], ["Identity expires", "NotAfter"], ["Configuration", "Enabled"]], fields: { ID: "string", UserID: "string", Name: "string", Platform: "string", Enabled: "boolean", NotAfter: "date" } },
    resources: { title: "Resources", description: "The current revision of each explicitly defined destination.", columns: [["Resource", "Name", "ID"], ["Destination", "Address", "Port"], ["Connector", "ConnectorID"], ["Kind / protocol", "Kind", "Protocol"], ["Revision", "Revision"], ["Configuration", "Enabled"]], fields: { ID: "string", Revision: "number", Name: "string", ConnectorID: "string", Kind: "string", Address: "string", Port: "number", Protocol: "string", Enabled: "boolean" } },
    connectors: { title: "Connectors", description: "Registered connectors. Enabled does not indicate that a connector is online.", columns: [["Connector", "Name", "ID"], ["Reported version", "Version"], ["Configuration", "Enabled"]], fields: { ID: "string", Name: "string", Version: "string", Enabled: "boolean" } },
    enrollments: { title: "Enrollments", description: "Enrollment progress and expiry, without invitation secrets.", columns: [["Enrollment", "ID"], ["Principal", "PrincipalID"], ["Profile / state", "Profile", "State"], ["Invitation expires", "ExpiresAt"], ["Identity expires", "NotAfter"], ["Issuer", "IssuerID"]], fields: { ID: "string", IssuerID: "string", PrincipalID: "string", Profile: "string", State: "string", ExpiresAt: "date", NotAfter: "date" } },
    certificates: { title: "Certificates", description: "Issued identity metadata and revocation state.", columns: [["Certificate", "ID"], ["Principal / profile", "PrincipalID", "Profile"], ["Valid from", "NotBefore"], ["Expires", "NotAfter"], ["Revocation", "Revoked"], ["Issuer", "IssuerID"]], fields: { ID: "string", IssuerID: "string", PrincipalID: "string", Profile: "string", NotBefore: "date", NotAfter: "date", Revoked: "boolean" } }
  };
  const byID = (id) => document.getElementById(id);
  const records = byID("records");
  const feedback = byID("feedback");
  const inventory = document.querySelector(".inventory");
  const nextButton = byID("next");
  const previousButton = byID("previous");
  let section = "users", revision = 0, next = "", cursors = [""], pageIndex = 0;
  let pending, generation = 0;

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
    records.replaceChildren();
    byID("revision").textContent = "";
    byID("page-summary").textContent = "Inventory unavailable";
    nextButton.disabled = true;
    previousButton.disabled = true;
  }
  function reset() {
    revision = 0; next = ""; cursors = [""]; pageIndex = 0;
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
    return data.Items.every((item) => item && Object.keys(item).length === Object.keys(fields).length && Object.entries(fields).every(([key, type]) => {
      const value = item[key];
      if (type === "date") return typeof value === "string" && value.length < 64 && Number.isFinite(Date.parse(value));
      if (type === "number") return Number.isSafeInteger(value) && value >= 0;
      return typeof value === type && (type !== "string" || value.length <= 4096);
    }));
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
      body.append(row);
    }
    table.append(body);
    const wrapper = element("div", undefined, "table-wrap"); wrapper.append(table);
    records.replaceChildren(wrapper);
    byID("page-summary").textContent = `${data.Items.length} ${data.Items.length === 1 ? "record" : "records"} on this page`;
    byID("revision").textContent = `Policy revision ${data.PolicyRevision}`;
    byID("page-number").textContent = `Page ${pageIndex + 1}`;
    message(data.Items.length ? `${view.title} loaded. Configuration does not establish effective access.` : `No ${section} to display.`);
  }
  async function load() {
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
  function select() {
    const candidate = location.hash.slice(1);
    if (candidate === "content") return;
    section = Object.hasOwn(sections, candidate) ? candidate : "users";
    for (const link of document.querySelectorAll("nav [data-section]")) {
      if (link.dataset.section === section) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    byID("page-title").textContent = sections[section].title;
    byID("page-description").textContent = sections[section].description;
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
