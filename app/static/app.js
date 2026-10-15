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
  setPill($("#fw-status"), state.firewall_enforced ? "nft enforced" : "nft off", state.firewall_enforced ? "ok" : "warn");
  const verifyTls = state.settings?.verify_upstream_tls !== false;
  $("#tls-status").hidden = verifyTls;
  setPill($("#tls-status"), "upstream tls unverified", "warn");
  $("#set-verify-tls").checked = verifyTls;
  const a = state.apply || {};
  if (a.ok === false) setPill($("#apply-status"), "apply failed", "bad");
  else if (a.at) {
    const extra = a.unresolved && a.unresolved.length ? ` · unresolved: ${a.unresolved.join(", ")}` : "";
    setPill($("#apply-status"), "applied " + new Date(a.at * 1000).toLocaleTimeString([], { hour12: false }) + extra, extra ? "warn" : "ok");
  }
}

// ------------------------------------------------------------------ rule tables

function setupRuleUIs() {
  const tpl = $("#rule-ui-tpl");
  for (const host of $$(".rule-ui")) {
    const kind = host.dataset.kind;
    host.appendChild(tpl.content.cloneNode(true));
    if (kind !== "tcp") $$(".tcp-only", host).forEach((el) => el.remove());
    $("tfoot td[colspan]", host).colSpan = kind === "deny" ? 2 : 3;
    if (kind !== "allow") $$(".allow-only", host).forEach((el) => el.remove());
    const form = $("form", host);
    form.target.placeholder = kind === "tcp" ? "IP, CIDR or hostname" : kind === "deny" ? "e.g. http://test.io/*" : "e.g. *.host.io";
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
    <td class="mono">${esc(r.target)}</td>
    ${r.kind === "allow" ? `<td class="c-ws"><span class="ws-check ${r.allow_websockets ? "allowed" : ""}" role="img" aria-label="WebSockets ${r.allow_websockets ? "allowed" : "denied"}" title="WebSockets ${r.allow_websockets ? "allowed" : "denied"}">${r.allow_websockets ? "✓" : "—"}</span></td>` : ""}
    ${r.kind === "tcp" ? `<td class="mono">${esc(r.proto)}/${esc(r.ports)}</td>` : ""}
    <td class="muted">${esc(r.comment)}</td>
    <td class="c-act"><button class="link edit">edit</button><button class="link danger del">delete</button></td>`;
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
    <td>${input("target", r.target)}</td>
    ${r.kind === "allow" ? `<td class="c-ws"><label class="switch"><input type="checkbox" name="allow_websockets" aria-label="Allow WebSockets" ${r.allow_websockets ? "checked" : ""}><span></span></label></td>` : ""}
    ${r.kind === "tcp" ? `<td class="nowrap"><select name="proto"><option ${r.proto === "tcp" ? "selected" : ""}>tcp</option><option ${r.proto === "udp" ? "selected" : ""}>udp</option></select>${input("ports", r.ports, "short")}</td>` : ""}
    <td>${input("comment", r.comment)}</td>
    <td class="c-act"><button class="link save">save</button><button class="link cancel">cancel</button></td>`;
  const val = (n) => $(`[name=${n}]`, tr)?.value.trim();
  const save = () => {
    const body = { name: val("name"), target: val("target"), comment: val("comment") };
    if (r.kind === "allow") body.allow_websockets = $("[name=allow_websockets]", tr).checked;
    if (r.kind === "tcp") Object.assign(body, { proto: val("proto"), ports: val("ports") });
    mutate("PUT", `/api/rules/${r.id}`, body);
  };
  $(".save", tr).addEventListener("click", save);
  $(".cancel", tr).addEventListener("click", render);
  $$("input", tr).forEach((i) => i.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") save();
    if (ev.key === "Escape") render();
  }));
  $("[name=target]", tr).focus();
}

function renderRules() {
  for (const host of $$(".rule-ui")) {
    const kind = host.dataset.kind;
    const body = $("tbody", host);
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

$("#reapply").addEventListener("click", async () => {
  if (await mutate("POST", "/api/reapply")) loadGenerated();
});

// ------------------------------------------------------------------ logs

const logs = { entries: [], paused: false, pending: [], max: 5000, shown: 1000 };

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
  return tr;
}

function renderLogs() {
  const rows = [];
  for (let i = logs.entries.length - 1; i >= 0 && rows.length < logs.shown; i--) {
    if (logMatches(logs.entries[i])) rows.push(logRow(logs.entries[i]));
  }
  $("#log-body").replaceChildren(...rows);
  $("#log-count").textContent = `${rows.length} shown / ${logs.entries.length} buffered`;
}

function addLog(e) {
  logs.entries.push(e);
  if (logs.entries.length > logs.max) logs.entries.splice(0, logs.entries.length - logs.max);
  if (!logMatches(e)) return;
  const body = $("#log-body");
  body.prepend(logRow(e));
  while (body.children.length > logs.shown) body.lastChild.remove();
  $("#log-count").textContent = `${body.children.length} shown / ${logs.entries.length} buffered`;
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
    if (logs.paused) logs.pending.push(e);
    else addLog(e);
  };
}

["#log-verdict", "#log-source"].forEach((s) => $(s).addEventListener("change", renderLogs));
$("#log-search").addEventListener("input", renderLogs);
$("#log-pause").addEventListener("click", (ev) => {
  logs.paused = !logs.paused;
  ev.currentTarget.textContent = logs.paused ? "resume" : "pause";
  if (!logs.paused) {
    logs.entries.push(...logs.pending);
    logs.pending = [];
    renderLogs();
  }
});
$("#log-clear").addEventListener("click", () => {
  logs.entries = [];
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
refresh();
startLogs();
setInterval(refresh, 10000);
let initialTab = "allow";
try { initialTab = location.hash.slice(1) || localStorage.getItem("agent-proxy-tab") || "allow"; } catch {}
activate($(`#tabs [data-tab=${initialTab}]`) ? initialTab : "allow");
