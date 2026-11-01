"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let state = { rules: [] };

// ------------------------------------------------------------------ api

async function api(method, url, body) {
  // resolve against origin: a page opened as http://user:pass@host/ cannot fetch relative URLs
  const res = await fetch(new URL(url, location.origin), {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
  return data;
}

function showError(msg) {
  const b = $("#error-banner");
  b.textContent = msg;
  b.hidden = !msg;
}

async function mutate(method, url, body) {
  try {
    setPill($("#apply-status"), "applying…", "busy");
    state = await api(method, url, body);
    showError("");
    render();
    return true;
  } catch (e) {
    showError(e.message);
    await refresh();
    return false;
  }
}

async function refresh() {
  try {
    state = await api("GET", "/api/state");
    // don't clobber a row that is being edited
    if ($("tr.editing")) renderStatus();
    else render();
  } catch (e) {
    showError(e.message);
  }
}

// ------------------------------------------------------------------ header

function setPill(el, text, cls) {
  el.textContent = text;
  el.className = "stat " + (cls || "");
}

function renderStatus() {
  setPill($("#squid-status"), state.squid_running ? "squid up" : "squid down", state.squid_running ? "ok" : "bad");
  setPill($("#fw-status"), state.firewall_enforced ? `nft ${state.firewall_mode || "container"}` : "nft off", state.firewall_enforced ? "ok" : "warn");
  $("#firewall-scope").textContent = state.firewall_mode === "gateway"
    ? `Forwarded traffic from ${state.gateway.agent_interface} to ${state.gateway.uplink_interface}. Other agent forwarding is rejected. Host traffic is managed separately.`
    : "Connections leaving the pod are rejected unless allowed, except the proxy's own traffic.";
  const verifyTls = state.settings?.verify_upstream_tls !== false;
  $("#tls-status").hidden = verifyTls;
  setPill($("#tls-status"), "upstream tls unverified", "warn");
  $("#set-verify-tls").checked = verifyTls;
  const form = $("#upstream-form");
  if (form.dataset.dirty !== "true") {
    $("#set-upstream-enabled").checked = !!state.settings?.upstream_proxy_enabled;
    $("#set-upstream-url").value = state.settings?.upstream_proxy_url || "";
    $("#set-upstream-user").value = state.settings?.upstream_proxy_username || "";
    $("#set-upstream-password").value = "";
    $("#set-upstream-password").placeholder = state.upstream_proxy_password_set ? "saved password (leave blank to keep)" : "password (optional)";
    $("#set-upstream-clear-password").checked = false;
  }
  const a = state.apply || {};
  if (a.ok === false) setPill($("#apply-status"), "apply failed", "bad");
  else if (a.at) {
    const extra = a.unresolved && a.unresolved.length ? ` · unresolved: ${a.unresolved.join(", ")}` : "";
    setPill($("#apply-status"), "applied " + new Date(a.at * 1000).toLocaleTimeString([], { hour12: false }) + extra, extra ? "warn" : "ok");
  }
}

// ------------------------------------------------------------------ rule tables

// Labels also identify fields when narrow tables become stacked tiles.
function labelRow(tr, labels) {
  [...tr.cells].forEach((cell, i) => {
    cell.dataset.label = labels[i];
    for (const control of $$("input, textarea, select", cell)) {
      if (!control.hasAttribute("aria-label")) control.setAttribute("aria-label", labels[i]);
    }
  });
}

function ruleLabels(kind) {
  return ["On", "Name", "Target(s)", ...(kind === "allow" ? ["WebSockets"] : []),
    ...(kind === "tcp" ? ["Proto/Ports"] : []), "Comment", "Actions"];
}

function setupTableResizing() {
  for (const table of $$("table")) {
    const headers = $$("thead th", table);
    headers.slice(0, -1).forEach((header, index) => {
      const neighbor = headers[index + 1];
      const handle = document.createElement("span");
      handle.className = "column-resizer";
      handle.tabIndex = 0;
      handle.setAttribute("role", "separator");
      handle.setAttribute("aria-orientation", "vertical");
      handle.setAttribute("aria-label", `Resize ${header.textContent.trim() || "Actions"} column`);
      handle.title = "Drag to resize; use arrow keys for fine adjustment";
      const freeze = () => {
        const total = table.getBoundingClientRect().width;
        const widths = headers.map((h) => h.getBoundingClientRect().width);
        headers.forEach((h, i) => { h.style.width = `${widths[i] / total * 100}%`; });
        return { width: widths[index], adjacent: widths[index + 1], total };
      };
      const resize = ({ width, adjacent, total }, delta) => {
        // Move the shared boundary; never increase the table's total width.
        const change = Math.max(Math.min(0, 48 - width), Math.min(delta, Math.max(0, adjacent - 48)));
        header.style.width = `${(width + change) / total * 100}%`;
        neighbor.style.width = `${(adjacent - change) / total * 100}%`;
        handle.setAttribute("aria-valuenow", Math.round(width + change));
      };
      handle.addEventListener("pointerdown", (ev) => {
        if (ev.button !== 0) return;
        ev.preventDefault();
        const sizes = freeze();
        const start = ev.clientX;
        handle.setPointerCapture(ev.pointerId);
        document.documentElement.classList.add("resizing-columns");
        const move = (event) => resize(sizes, event.clientX - start);
        const stop = () => {
          handle.removeEventListener("pointermove", move);
          handle.removeEventListener("lostpointercapture", stop);
          document.documentElement.classList.remove("resizing-columns");
        };
        handle.addEventListener("pointermove", move);
        handle.addEventListener("lostpointercapture", stop);
      });
      handle.addEventListener("keydown", (ev) => {
        if (!["ArrowLeft", "ArrowRight"].includes(ev.key)) return;
        ev.preventDefault();
        resize(freeze(),
          (ev.key === "ArrowRight" ? 1 : -1) * (ev.shiftKey ? 32 : 8));
      });
      header.appendChild(handle);
    });
  }
}

// Refit on input and on width changes (column dragging and tile breakpoints).
function fitTextarea(textarea) {
  if (!textarea.getClientRects().length) return;
  textarea.style.height = "auto";
  const style = getComputedStyle(textarea);
  textarea.style.height = `${textarea.scrollHeight + parseFloat(style.borderTopWidth) + parseFloat(style.borderBottomWidth)}px`;
}
const textareaWidths = new WeakMap();
const textareaObserver = new ResizeObserver((entries) => {
  for (const { target, contentRect } of entries) {
    if (!target.isConnected) { textareaObserver.unobserve(target); continue; }
    if (textareaWidths.get(target) === contentRect.width) continue;
    textareaWidths.set(target, contentRect.width);
    fitTextarea(target);
  }
});
function setupTextarea(textarea) {
  textarea.addEventListener("input", () => fitTextarea(textarea));
  textareaObserver.observe(textarea);
  fitTextarea(textarea);
}

function setupRuleUIs() {
  const tpl = $("#rule-ui-tpl");
  for (const host of $$(".rule-ui")) {
    const kind = host.dataset.kind;
    host.appendChild(tpl.content.cloneNode(true));
    if (kind !== "tcp") $$(".tcp-only", host).forEach((el) => el.remove());
    $("tfoot td[colspan]", host).colSpan = kind === "deny" ? 2 : 3;
    if (kind !== "allow") $$(".allow-only", host).forEach((el) => el.remove());
    const headers = $(`#${kind}-headers-tpl`);
    if (headers) $("thead", host).replaceChildren(headers.content.cloneNode(true));
    const form = $("form", host);
    if (kind === "tcp") {
      form.target.rows = 1;
      const controls = $(".add-controls", form);
      controls.prepend($(".add-network", controls));
    }
    setupTextarea(form.target);
    form.addEventListener("reset", () => requestAnimationFrame(() => fitTextarea(form.target)));
    form.target.setAttribute("aria-label", kind === "tcp" ? "Target" : "Targets separated by commas");
    form.target.placeholder = kind === "tcp" ? "IP, CIDR or hostname" : "e.g. https://test.host.io, *.host2.io";
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = { kind, target: form.target.value.trim(), name: form.name.value.trim(), comment: form.comment.value.trim() };
      if (kind === "allow") body.allow_websockets = form.allow_websockets.checked;
      if (kind === "tcp") Object.assign(body, { ports: form.ports.value.trim(), proto: form.proto.value });
      if (await mutate("POST", "/api/rules", body)) form.reset();
    });
  }
}

function ruleRow(r) {
  const tr = document.createElement("tr");
  tr.dataset.id = r.id;
  tr.className = r.enabled ? "" : "disabled";
  tr.innerHTML = `
    <td class="c-on"><label class="switch"><input type="checkbox" ${r.enabled ? "checked" : ""}><span></span></label></td>
    <td class="mono">${esc(r.name)}</td>
    <td class="mono">${r.kind === "tcp" ? esc(r.target) : `<span class="targets">${r.target.split(",").map((target) => `<span class="target">${esc(target.trim())}</span>`).join("")}</span>`}</td>
    ${r.kind === "allow" ? `<td class="c-ws"><span class="ws-check ${r.allow_websockets ? "allowed" : ""}" role="img" aria-label="WebSockets ${r.allow_websockets ? "allowed" : "denied"}" title="WebSockets ${r.allow_websockets ? "allowed" : "denied"}">${r.allow_websockets ? "✓" : "—"}</span></td>` : ""}
    ${r.kind === "tcp" ? `<td class="mono">${esc(r.proto)}/${esc(r.ports)}</td>` : ""}
    <td class="muted">${esc(r.comment)}</td>
    <td class="c-act"><span class="row-actions"><button class="link edit">edit</button><button class="link danger del">delete</button></span></td>`;
  labelRow(tr, ruleLabels(r.kind));
  $("input[type=checkbox]", tr).addEventListener("change", (ev) => mutate("PUT", `/api/rules/${r.id}`, { enabled: ev.target.checked }));
  $(".edit", tr).addEventListener("click", () => editRow(tr, r));
  const del = $(".del", tr);
  del.addEventListener("click", () => {
    if (del.dataset.armed) return mutate("DELETE", `/api/rules/${r.id}`);
    del.dataset.armed = "1";
    del.textContent = "confirm";
    setTimeout(() => { delete del.dataset.armed; del.textContent = "delete"; }, 3000);
  });
  return tr;
}

function editRow(tr, r) {
  tr.classList.add("editing");
  const input = (name, val, cls = "") => `<input name="${name}" value="${esc(val)}" class="${cls}">`;
  tr.innerHTML = `
    <td class="c-on"></td>
    <td>${input("name", r.name)}</td>
    <td><textarea name="target" rows="1" aria-label="Targets">${esc(r.target)}</textarea></td>
    ${r.kind === "allow" ? `<td class="c-ws"><label class="switch"><input type="checkbox" name="allow_websockets" aria-label="Allow WebSockets" ${r.allow_websockets ? "checked" : ""}><span></span></label></td>` : ""}
    ${r.kind === "tcp" ? `<td class="nowrap"><select name="proto"><option ${r.proto === "tcp" ? "selected" : ""}>tcp</option><option ${r.proto === "udp" ? "selected" : ""}>udp</option></select>${input("ports", r.ports, "short")}</td>` : ""}
    <td>${input("comment", r.comment)}</td>
    <td class="c-act"><span class="row-actions"><button class="link save">save</button><button class="link cancel">cancel</button></span></td>`;
  labelRow(tr, ruleLabels(r.kind));
  const val = (n) => $(`[name=${n}]`, tr)?.value.trim();
  const save = () => {
    const body = { name: val("name"), target: val("target"), comment: val("comment") };
    if (r.kind === "allow") body.allow_websockets = $("[name=allow_websockets]", tr).checked;
    if (r.kind === "tcp") Object.assign(body, { proto: val("proto"), ports: val("ports") });
    mutate("PUT", `/api/rules/${r.id}`, body);
  };
  $(".save", tr).addEventListener("click", save);
  $(".cancel", tr).addEventListener("click", render);
  $$("input, textarea", tr).forEach((i) => i.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (i.tagName !== "TEXTAREA" || ev.ctrlKey || ev.metaKey)) {
      ev.preventDefault();
      save();
    }
    if (ev.key === "Escape") render();
  }));
  setupTextarea($("[name=target]", tr));
  $("[name=target]", tr).focus();
}

function renderRules() {
  for (const host of $$(".rule-ui")) {
    const kind = host.dataset.kind;
    const body = $("tbody", host);
    $$("textarea", body).forEach((textarea) => textareaObserver.unobserve(textarea));
    body.replaceChildren(...state.rules.filter((r) => r.kind === kind).map(ruleRow));
    const n = state.rules.filter((r) => r.kind === kind && r.enabled).length;
    $(`#tabs [data-tab=${kind}]`).dataset.count = n;
  }
}

function render() {
  renderStatus();
  renderRules();
}

// ------------------------------------------------------------------ tabs

function activate(tab) {
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $$(".tab").forEach((s) => s.classList.toggle("active", s.id === `tab-${tab}`));
  if (tab === "ca") loadCA();
  if (tab === "config") loadGenerated();
  try { localStorage.setItem("agent-proxy-tab", tab); } catch {}
  history.replaceState(null, "", `#${tab}`);
}

$$("#tabs button").forEach((b) => b.addEventListener("click", () => activate(b.dataset.tab)));

// ------------------------------------------------------------------ CA

async function loadCA() {
  try {
    const ca = await api("GET", "/api/ca");
    $("#ca-pem").value = ca.pem;
    $("#ca-subject").textContent = ca.subject;
    $("#ca-expiry").textContent = ca.not_after;
    $("#ca-fp").textContent = ca.sha256;
    const url = `http://127.0.0.1:${ca.ui_port}/ca.crt`;  // as seen from inside the pod
    $("#ca-url").textContent = url;
    $("#snip-debian").textContent = `curl -fsSo /usr/local/share/ca-certificates/agent-proxy.crt ${url}\nupdate-ca-certificates`;
    $("#snip-rhel").textContent = `curl -fsSo /etc/pki/ca-trust/source/anchors/agent-proxy.crt ${url}\nupdate-ca-trust`;
    $("#snip-alpine").textContent = `wget -qO /usr/local/share/ca-certificates/agent-proxy.crt ${url}\nupdate-ca-certificates`;
    $("#snip-env").textContent = [
      "export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-proxy.crt",
      "export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt   # python requests",
      "export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt        # python ssl, go, ...",
      "export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128",
      "export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY NO_PROXY=localhost,127.0.0.1",
    ].join("\n");
  } catch (e) {
    showError(e.message);
  }
}

$("#ca-copy").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  try {
    await navigator.clipboard.writeText($("#ca-pem").value);
  } catch {
    $("#ca-pem").select();
    document.execCommand("copy");
  }
  btn.textContent = "copied";
  setTimeout(() => (btn.textContent = "copy pem"), 1500);
});

// ------------------------------------------------------------------ config

async function loadGenerated() {
  try {
    const g = await api("GET", "/api/generated");
    $("#gen-squid").textContent = g.squid;
    $("#gen-nft").textContent = g.nft;
  } catch (e) {
    showError(e.message);
  }
}

$("#import-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  let doc;
  try {
    doc = JSON.parse(await file.text());
  } catch {
    return showError(`${file.name} is not valid JSON`);
  }
  const mode = $("input[name=import-mode]:checked").value;
  if (await mutate("POST", `/api/import?mode=${mode}`, doc)) loadGenerated();
});

$("#set-verify-tls").addEventListener("change", async (ev) => {
  if (await mutate("PUT", "/api/settings", { verify_upstream_tls: ev.target.checked })) loadGenerated();
});

$("#upstream-form").addEventListener("input", (ev) => { ev.currentTarget.dataset.dirty = "true"; });
$("#upstream-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const button = ev.currentTarget.querySelector("button");
  button.disabled = true;
  const settings = {
    upstream_proxy_enabled: $("#set-upstream-enabled").checked,
    upstream_proxy_url: $("#set-upstream-url").value.trim(),
    upstream_proxy_username: $("#set-upstream-user").value,
  };
  const password = $("#set-upstream-password").value;
  if (password || $("#set-upstream-clear-password").checked) settings.upstream_proxy_password = password;
  try {
    if (await mutate("PUT", "/api/settings", settings)) {
      $("#upstream-form").dataset.dirty = "false";
      renderStatus();
      loadGenerated();
    }
  } finally { button.disabled = false; }
});

$("#reapply").addEventListener("click", async () => {
  if (await mutate("POST", "/api/reapply")) loadGenerated();
});

// ------------------------------------------------------------------ logs

const logs = { entries: [], paused: false, pending: [], max: 5000, shown: 1000 };

function updateLogCounts() {
  const count = Math.min(logs.entries.length + logs.pending.length, logs.max);
  const tab = $('#tabs [data-tab="logs"]');
  tab.dataset.count = count;
  tab.setAttribute("aria-label", `Logs: ${count} ${count === 1 ? "entry" : "entries"}`);
  tab.title = `${count} buffered log entries (including paused entries)`;
  const pending = logs.pending.length ? ` · ${logs.pending.length} pending` : "";
  $("#log-count").textContent = `${$("#log-body").children.length} shown / ${logs.entries.length} buffered${pending}`;
}

function logMatches(e) {
  const v = $("#log-verdict").value, s = $("#log-source").value, q = $("#log-search").value.trim().toLowerCase();
  if (v && e.verdict !== v) return false;
  if (s && e.source !== s) return false;
  if (q && ![e.host, e.path, e.rule, e.client, e.method, e.url].some((x) => String(x || "").toLowerCase().includes(q))) return false;
  return true;
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
const fmtTime = (d) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;

async function copyLogText(value) {
  try {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Clipboard API is unavailable on ordinary HTTP gateway addresses.
      const input = document.createElement("textarea");
      input.value = value;
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.appendChild(input);
      const previousFocus = document.activeElement;
      try {
        input.select();
        if (!document.execCommand("copy")) throw new Error("Clipboard unavailable");
      } finally {
        input.remove();
        previousFocus?.focus({ preventScroll: true });
      }
    }
  } catch {
    showError("Unable to copy to clipboard.");
  }
}

function logRow(e) {
  const d = new Date(e.ts);
  const tr = document.createElement("tr");
  tr.className = e.verdict === "DENY" ? "deny" : "allow";
  tr.title = `${e.url}\n${e.detail || ""}`;
  tr.innerHTML = `
    <td class="nowrap mono muted">${fmtTime(d)}</td>
    <td class="mono verdict">${e.verdict === "DENY" ? "deny" : "allow"}</td>
    <td class="mono">${esc(e.rule || "—")}</td>
    <td class="mono">${esc(e.method)}</td>
    <td class="mono">${esc(e.host)}</td>
    <td class="mono path">${esc(e.path)}</td>
    <td class="mono">${esc(e.status)}</td>
    <td class="mono muted">${esc(e.client)}</td>`;
  labelRow(tr, ["Date", "Verdict", "Rule", "Method", "Host", "Path", "Status", "Client"]);
  for (const [cell, value, label] of [
    [tr.cells[4], e.host, "host"],
    [tr.cells[5], e.url, "full URL"],
  ]) {
    cell.title = "";
    if (typeof value === "string" && value) {
      cell.classList.add("copy-url");
      cell.tabIndex = 0;
      cell.setAttribute("role", "button");
      cell.setAttribute("aria-label", `Copy ${label}: ${value}`);
      cell.addEventListener("click", () => copyLogText(value));
      cell.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          copyLogText(value);
        }
      });
    }
  }
  return tr;
}

function renderLogs() {
  const rows = [];
  for (let i = logs.entries.length - 1; i >= 0 && rows.length < logs.shown; i--) {
    if (logMatches(logs.entries[i])) rows.push(logRow(logs.entries[i]));
  }
  $("#log-body").replaceChildren(...rows);
  updateLogCounts();
}

function addLog(e) {
  logs.entries.push(e);
  if (logs.entries.length > logs.max) logs.entries.splice(0, logs.entries.length - logs.max);
  if (!logMatches(e)) {
    updateLogCounts();
    return;
  }
  const body = $("#log-body");
  body.prepend(logRow(e));
  while (body.children.length > logs.shown) body.lastChild.remove();
  updateLogCounts();
}

async function startLogs() {
  try {
    logs.entries = await api("GET", "/api/logs?limit=2000");
  } catch (e) {
    showError(e.message);
  }
  renderLogs();
  const es = new EventSource("/api/logs/stream");
  es.onopen = () => setPill($("#log-live"), "live", "ok");
  es.onerror = () => setPill($("#log-live"), "reconnecting…", "warn");
  es.onmessage = (m) => {
    const e = JSON.parse(m.data);
    if (logs.paused) {
      logs.pending.push(e);
      if (logs.pending.length > logs.max) logs.pending.splice(0, logs.pending.length - logs.max);
      updateLogCounts();
    } else addLog(e);
  };
}

["#log-verdict", "#log-source"].forEach((s) => $(s).addEventListener("change", renderLogs));
$("#log-search").addEventListener("input", renderLogs);
$("#log-pause").addEventListener("click", (ev) => {
  logs.paused = !logs.paused;
  ev.currentTarget.textContent = logs.paused ? "resume" : "pause";
  if (!logs.paused) {
    logs.entries.push(...logs.pending);
    if (logs.entries.length > logs.max) logs.entries.splice(0, logs.entries.length - logs.max);
    logs.pending = [];
    renderLogs();
  }
});
$("#log-clear").addEventListener("click", () => {
  logs.entries = [];
  logs.pending = [];
  renderLogs();
});

// ------------------------------------------------------------------ theme

function setTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  $$("[data-theme-set]").forEach((b) => b.classList.toggle("active", b.dataset.themeSet === (t || "auto")));
  try { t && t !== "auto" ? localStorage.setItem("agent-proxy-theme", t) : localStorage.removeItem("agent-proxy-theme"); } catch {}
}
$$("[data-theme-set]").forEach((b) => b.addEventListener("click", () => setTheme(b.dataset.themeSet)));
setTheme(document.documentElement.dataset.theme || "auto");

// ------------------------------------------------------------------ boot

setupRuleUIs();
setupTableResizing();
refresh();
startLogs();
setInterval(refresh, 10000);
let initialTab = "allow";
try { initialTab = location.hash.slice(1) || localStorage.getItem("agent-proxy-tab") || "allow"; } catch {}
activate($(`#tabs [data-tab=${initialTab}]`) ? initialTab : "allow");
