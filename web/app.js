/* Root-Defense Witness Console */
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
const short = (h, n = 10) => (h ? `${h.slice(0, n)}…${h.slice(-6)}` : "—");
const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleTimeString([], { hour12: false }) : "—");
const fmtDateTime = (t) => (t ? new Date(t * 1000).toLocaleString([], { hour12: false }) : "—");
const num = (n) => (n ?? 0).toLocaleString();
const REASONS = { 0: "scheduled", 1: "critical event", 2: "alarm" };

async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!r.ok) {
    let d = r.statusText;
    try { d = (await r.json()).detail || d; } catch (_) {}
    throw new Error(d);
  }
  return r.json();
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 3000);
}

/* ---------------------------------------------------------------- navigation */
let view = "monitor";
function show(v) {
  view = v;
  $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.view === v));
  $$(".view").forEach((s) => s.classList.toggle("active", s.id === `view-${v}`));
  if (v === "chain") loadChain();
  if (v === "compliance") loadCompliance();
  if (v === "auditor") fillAgents();
  history.replaceState(null, "", `#${v}`);
}
$$(".tab").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

/* ---------------------------------------------------------------- sound */
let sound = true;
let audioCtx = null;
$("#soundBtn").classList.add("on");
$("#soundBtn").addEventListener("click", () => {
  sound = !sound;
  $("#soundBtn").classList.toggle("on", sound);
  $("#soundWaves").style.display = sound ? "" : "none";
});
function beep() {
  if (!sound) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    [0, 0.22, 0.44].forEach((d) => {
      const o = audioCtx.createOscillator();
      const g = audioCtx.createGain();
      o.type = "square";
      o.frequency.value = 880;
      g.gain.setValueAtTime(0.06, audioCtx.currentTime + d);
      g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + d + 0.16);
      o.connect(g).connect(audioCtx.destination);
      o.start(audioCtx.currentTime + d);
      o.stop(audioCtx.currentTime + d + 0.17);
    });
  } catch (_) {}
}

/* ---------------------------------------------------------------- monitor */
let overview = null;
let lastAlarmId = 0;
let streamKind = "";
let seenRows = new Set();
let agentsCache = [];

function renderOverview(o) {
  overview = o;
  agentsCache = o.agents;
  $("#footVersion").textContent = `v${o.version}`;
  // chain pill
  const ch = o.chain || {};
  const pill = $("#chainPill");
  const ok = ch.connected && ch.contract_ok && o.chain.ok !== false;
  pill.className = `pill ${ok ? "ok" : ch.connected ? "warn" : "bad"}`;
  const net = ch.mode === "quai" ? "Quai Orchard" : "Local EVM";
  pill.innerHTML = `<span class="dot"></span><span>${net}${ch.block != null ? ` · block #${num(ch.block)}` : ""}${ch.connected ? "" : " · offline"}</span>`;

  // agent KPI
  const a = o.agents[0];
  const card = $("#kpiAgent");
  if (!a) {
    card.className = "kpi kpi-agent";
    $("#agentState").textContent = "NO AGENT";
    $("#agentFoot").textContent = "start ./rd up-agent on System A";
  } else {
    const silent = a.status === "silent";
    card.className = `kpi kpi-agent ${silent ? "silent" : "online"}`;
    $("#agentState").textContent = silent ? "SILENT" : "ONLINE";
    const hb = a.last_heartbeat ? Math.max(0, o.now - a.last_heartbeat).toFixed(1) : "—";
    $("#agentFoot").innerHTML = silent
      ? `<b>${esc(a.agent_id)}</b> · no signed heartbeat for ${a.seconds_since_seen.toFixed(0)}s`
      : `<b>${esc(a.agent_id)}</b> · heartbeat ${hb}s ago · epoch ${a.epoch}`;
  }
  const t = o.totals;
  $("#kEntries").textContent = num(t.entries);
  $("#kEntriesFoot").textContent = `${num(t.logs)} log lines · ${num(t.heartbeats)} heartbeats`;
  $("#kAnchored").textContent = num(t.anchored_entries);
  $("#kAnchoredFoot").textContent = `${num(t.batches)} batches · ${num(t.pending_entries)} pending`;
  $("#kDetect").textContent = t.last_detection_seconds != null ? `${t.last_detection_seconds.toFixed(1)} s` : "—";
  $("#kAlarms").textContent = o.alarms.length;
  $("#kpiAlarms").classList.toggle("hot", o.alarms.length > 0);
  $("#kAlarmsFoot").textContent = o.alarms.length ? "action required" : "all clear";
  $("#anchorEvery").textContent = `every ${o.config.anchor_interval}s + on critical events`;
  renderAlarm(o.alarms);
}

function renderAlarm(alarms) {
  const b = $("#alarmBanner");
  if (!alarms.length) {
    b.classList.add("hidden");
    return;
  }
  const a = alarms[0];
  b.classList.remove("hidden");
  $("#alarmTitle").textContent = a.title;
  const extra = alarms.length > 1 ? ` · ${alarms.length - 1} more open alarm(s)` : "";
  $("#alarmSub").textContent = `${fmtDateTime(a.ts)} · ${a.type.replaceAll("_", " ")}${extra} · evidence anchored on-chain`;
  const d = a.detail || {};
  let metric = "";
  if (a.type === "TAMPER_DETECTED" && d.alarm_seconds != null) metric = `<b>${d.alarm_seconds.toFixed(1)}s</b><span>edit → alarm</span>`;
  else if (a.type === "AGENT_SILENT") metric = `<b>${(d.silent_seconds ?? 0).toFixed(1)}s</b><span>silence → alarm</span>`;
  $("#alarmMetric").innerHTML = metric;
  $("#alarmAck").onclick = async () => { await api(`/api/v1/events/${a.id}/ack`, { method: "POST" }); refresh(); };
  $("#alarmInvestigate").onclick = () => { show("auditor"); if (a.agent_id) $("#auditAgent").value = a.agent_id; };
  if (a.id > lastAlarmId) {
    if (lastAlarmId) beep();
    lastAlarmId = a.id;
  }
}

function kindBadge(e) {
  if (e.kind === "log" && e.meta && e.meta.critical) return `<span class="badge b-critical">privileged</span>`;
  return `<span class="badge b-${esc(e.kind)}">${esc(e.kind)}</span>`;
}

function entryContent(e) {
  if (e.kind === "log") return esc(e.line);
  if (e.kind === "heartbeat") {
    const lines = Object.entries(e.meta.lines || {}).map(([k, v]) => `${k}: ${v}`).join(" · ");
    return `<span style="color:var(--muted)">signed heartbeat · uptime ${Math.round(e.meta.uptime || 0)}s · ${esc(lines)}</span>`;
  }
  if (e.kind === "tamper") {
    const ops = (e.meta.ops || []).map((o) => o.type === "inserted" ? `lines inserted before ${o.before_line}` :
      o.lines[0] === o.lines[1] ? `line ${o.lines[0]} ${o.type}` : `lines ${o.lines[0]}–${o.lines[1]} ${o.type}`).join(", ");
    return `<b style="color:#FB7185">TAMPERING REPORTED: ${esc(ops)}</b>`;
  }
  return "";
}

async function loadStream() {
  const rows = await api(`/api/v1/entries?limit=60${streamKind ? `&kind=${streamKind}` : ""}`);
  const body = $("#streamBody");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">No entries yet. Start the agent on System A.</td></tr>`;
    return;
  }
  const first = seenRows.size === 0;
  body.innerHTML = rows.map((e) => {
    const key = `${e.agent_id}:${e.seq}:${e.anchored}`;
    const isNew = !first && !seenRows.has(`${e.agent_id}:${e.seq}`);
    const cls = [isNew ? "new" : "", e.kind === "tamper" ? "row-tamper" : "", e.meta && e.meta.critical ? "row-critical" : ""].join(" ");
    return `<tr class="${cls}" title="hash ${esc(e.hash)}&#10;signature ${esc(e.sig.slice(0, 32))}…&#10;next key ${esc(e.next_pk.slice(0, 32))}…">
      <td class="mono">${fmtTime(e.ts)}</td>
      <td class="mono">${e.seq}</td>
      <td>${kindBadge(e)}</td>
      <td class="mono">${e.source ? esc(e.source) + (e.line_no ? `:${e.line_no}` : "") : "—"}</td>
      <td class="content">${entryContent(e)}</td>
      <td>${e.anchored ? `<span class="proof-ok">✓ on-chain</span>` : `<span class="proof-pending">◷ witness</span>`}</td></tr>`;
  }).join("");
  rows.forEach((e) => seenRows.add(`${e.agent_id}:${e.seq}`));
}
$$("#streamFilter .seg-btn").forEach((b) => b.addEventListener("click", () => {
  $$("#streamFilter .seg-btn").forEach((x) => x.classList.toggle("active", x === b));
  streamKind = b.dataset.kind;
  seenRows = new Set();
  loadStream();
}));

async function loadEvents() {
  const evs = await api("/api/v1/events?limit=40");
  $("#eventFeed").innerHTML = evs.length ? evs.map((e) => `
    <li class="${e.acked_at ? "acked" : ""}">
      <span class="sev sev-${esc(e.severity)}"></span>
      <div><div class="t">${esc(e.title)}</div>
      <div class="m">${fmtDateTime(e.ts)} · ${e.anchor_tx ? `anchored ${e.anchor_explorer ? `<a href="${esc(e.anchor_explorer)}" target="_blank">${short(e.anchor_tx, 8)}</a>` : `<span class="mono">${short(e.anchor_tx, 8)}</span>`}` : "anchoring…"}</div></div>
    </li>`).join("") : `<li class="empty">No events yet.</li>`;
}
$("#ackAll").addEventListener("click", async () => { await api("/api/v1/events/ack-all", { method: "POST" }); refresh(); });

async function loadAnchors() {
  const bs = await api("/api/v1/batches?limit=12");
  $("#anchorList").innerHTML = bs.length ? bs.map((b) => `
    <li><div><div class="root">${short(b.root, 12)}</div><div class="meta">${num(b.count)} entries · #${b.first_seq}–#${b.last_seq} · ${REASONS[b.reason]}</div></div>
    <div style="text-align:right"><div class="meta">${fmtTime(b.created_at)}</div><div class="meta">block ${b.block_number ?? "—"}</div></div></li>`).join("")
    : `<li class="empty">No anchors yet.</li>`;
}

async function refresh() {
  try {
    renderOverview(await api("/api/v1/overview"));
    if (view === "monitor") await Promise.all([loadStream(), loadEvents(), loadAnchors()]);
  } catch (e) {
    $("#chainPill").className = "pill bad";
    $("#chainPill").innerHTML = `<span class="dot"></span><span>Witness unreachable</span>`;
  }
}

/* ---------------------------------------------------------------- auditor */
function fillAgents() {
  const sel = $("#auditAgent");
  const cur = sel.value;
  sel.innerHTML = agentsCache.map((a) => `<option value="${esc(a.agent_id)}">${esc(a.agent_id)} (${esc(a.hostname || "")})</option>`).join("")
    || `<option value="">no agents</option>`;
  if (cur) sel.value = cur;
}

function setStatus(html, spin = true) {
  const s = $("#auditStatus");
  s.classList.remove("hidden");
  s.innerHTML = `${spin ? `<div class="spinner"></div>` : ""}<div>${html}</div>`;
}

function busy(on) {
  ["#btnCollect", "#btnHistory"].forEach((id) => ($(id).disabled = on));
}

$("#btnCollect").addEventListener("click", async () => {
  const agent = $("#auditAgent").value;
  if (!agent) return toast("No agent enrolled yet");
  busy(true);
  $("#auditResult").innerHTML = "";
  setStatus(`Requesting the current log files from <b>${esc(agent)}</b>…`);
  try {
    const { request_id } = await api("/api/v1/audit/collect", { method: "POST", body: JSON.stringify({ agent_id: agent }) });
    for (;;) {
      await new Promise((r) => setTimeout(r, 600));
      const st = await api(`/api/v1/audit/collect/${request_id}`);
      if (st.status === "done") {
        setStatus("Recomputing hashes, signatures and Merkle proofs against the blockchain…");
        renderReport(await api(`/api/v1/audit/report/${st.report_id}`));
        break;
      }
      if (st.status === "timeout") {
        setStatus(`The agent on <b>${esc(agent)}</b> did not answer, so it may have been killed. Copy the log files off the server and use <b>Upload log files</b>, or run <b>Verify witness vs blockchain</b>.`, false);
        break;
      }
    }
  } catch (e) {
    setStatus(`Error: ${esc(e.message)}`, false);
  } finally {
    busy(false);
  }
});

$("#btnHistory").addEventListener("click", async () => {
  busy(true);
  $("#auditResult").innerHTML = "";
  setStatus("Recomputing every hash link, signature and Merkle root and comparing with the contract…");
  try {
    const agent = $("#auditAgent").value;
    renderReport(await api(`/api/v1/audit/history${agent ? `?agent_id=${encodeURIComponent(agent)}` : ""}`));
  } catch (e) {
    setStatus(`Error: ${esc(e.message)}`, false);
  } finally {
    busy(false);
  }
});

$("#uploadInput").addEventListener("change", async (ev) => {
  const files = Array.from(ev.target.files || []);
  if (!files.length) return;
  const agent = $("#auditAgent").value;
  const payload = {};
  for (const f of files) payload[f.name] = await f.text();
  setStatus(`Verifying ${files.length} uploaded file(s)…`);
  try {
    renderReport(await api("/api/v1/audit/upload", { method: "POST", body: JSON.stringify({ agent_id: agent, files: payload }) }));
  } catch (e) {
    setStatus(`Error: ${esc(e.message)}`, false);
  }
  ev.target.value = "";
});

const ICONS = {
  GENUINE: `<svg viewBox="0 0 24 24" width="38" height="38" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>`,
  TAMPERED: `<svg viewBox="0 0 24 24" width="38" height="38" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z"/><path d="M12 8v5M12 16.5h.01"/></svg>`,
  UNVERIFIED: `<svg viewBox="0 0 24 24" width="38" height="38" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`,
};

function diff(a, b) {
  if (a == null || b == null) return [esc(a), esc(b)];
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let s = 0;
  while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
  const mid = (x) => x.slice(p, x.length - s);
  return [
    `${esc(a.slice(0, p))}<del>${esc(mid(a))}</del>${esc(a.slice(a.length - s))}`,
    `${esc(b.slice(0, p))}<ins>${esc(mid(b))}</ins>${esc(b.slice(b.length - s))}`,
  ];
}

function renderReport(r) {
  $("#auditStatus").classList.add("hidden");
  const meta = `${r.kind === "logs" ? esc(r.origin) : "Witness history checked against the blockchain"} · ${fmtDateTime(r.created_at)} · report ${esc(r.id)} · ${esc(r.chain.label)}`;
  let html = `
  <div class="verdict v-${r.verdict}">
    <div class="verdict-icon">${ICONS[r.verdict]}</div>
    <div><div class="verdict-label">${r.verdict}</div><div class="verdict-head">${esc(r.headline)}</div><div class="verdict-meta">${meta}</div></div>
    <div><a class="btn ${r.verdict === "TAMPERED" ? "btn-light" : "btn-primary"}" href="/api/v1/audit/bundle/${esc(r.id)}">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 3v12m0 0-5-5m5 5 5-5M4 21h16"/></svg>
      Download proof bundle</a></div>
  </div>`;

  if (r.kind === "logs") {
    const c = r.counts;
    const h = r.history;
    const lines = r.sources.reduce((s, x) => s + x.authentic_lines, 0);
    const matching = r.sources.reduce((s, x) => s + x.matching, 0);
    const det = r.last_detection;
    html += `<div class="stats">
      <div class="stat ${matching === lines ? "good" : ""}"><b>${num(matching)} / ${num(lines)}</b><span>witnessed lines still intact</span></div>
      <div class="stat ${c.modified ? "bad" : ""}"><b>${c.modified}</b><span>lines modified</span></div>
      <div class="stat ${c.deleted + c.file_missing ? "bad" : ""}"><b>${c.deleted + c.file_missing}</b><span>lines deleted</span></div>
      <div class="stat ${c.inserted ? "warn" : ""}"><b>${c.inserted}</b><span>lines inserted (fake)</span></div>
      <div class="stat ${h.batches_verified === h.batches_total ? "good" : "warn"}"><b>${h.batches_verified} / ${h.batches_total}</b><span>Merkle roots verified on-chain</span></div>
      <div class="stat good"><b>${num(h.signatures_ok)}</b><span>forward-secure signatures valid</span></div>
      ${det && det.alarm_seconds != null ? `<div class="stat"><b>${det.alarm_seconds.toFixed(1)} s</b><span>from edit to alarm</span></div>` : ""}
    </div>`;
    const rows = r.findings.filter((f) => f.type !== "unrecorded");
    const unrec = r.findings.length - rows.length;
    html += `<div class="panel result-panel"><div class="panel-head"><div><h2>Findings</h2>
      <p class="muted">Each changed line is located exactly and backed by a Merkle inclusion proof against the on-chain root.${unrec ? ` ${unrec} newer line(s) were not yet witnessed and are listed last.` : ""}</p></div></div>
      <div class="table-wrap"><table class="tbl"><thead><tr><th>Change</th><th>Location</th><th>Witnessed original → current on server</th><th>Recorded</th><th>Anchor</th><th>Proof</th></tr></thead><tbody>
      ${r.findings.length ? r.findings.map(findingRow).join("") : `<tr><td colspan="6" class="empty">No differences. Every line matches the witnessed record.</td></tr>`}
      </tbody></table></div></div>`;
  } else {
    const a = r.agents;
    const tot = (k) => a.reduce((s, x) => s + (x[k] || 0), 0);
    html += `<div class="stats">
      <div class="stat good"><b>${num(tot("entries_checked"))}</b><span>entries re-verified</span></div>
      <div class="stat ${tot("links_ok") === tot("entries_checked") ? "good" : "bad"}"><b>${num(tot("links_ok"))}</b><span>hash-chain links intact</span></div>
      <div class="stat ${tot("batches_verified") === tot("batches_total") ? "good" : "bad"}"><b>${tot("batches_verified")} / ${tot("batches_total")}</b><span>batches match on-chain roots</span></div>
      <div class="stat"><b>${num(tot("pending_entries"))}</b><span>entries awaiting next anchor</span></div>
      <div class="stat ${r.events.events_failed ? "bad" : "good"}"><b>${r.events.events_verified}</b><span>alarms verified on-chain</span></div>
    </div>`;
    if (r.issues.length) {
      html += `<div class="panel result-panel"><h2>Problems found</h2><div class="table-wrap"><table class="tbl"><thead><tr><th>Where</th><th>Item</th><th>Problem</th></tr></thead><tbody>
        ${r.issues.map((i) => `<tr><td><span class="badge b-tamper">${esc(i.where)}</span></td><td class="mono">${i.seq != null ? `entry #${i.seq}` : `batch ${i.batch}`}</td><td>${esc(i.problem)}</td></tr>`).join("")}
        </tbody></table></div></div>`;
    }
  }
  html += batchTable(r.batches);
  $("#auditResult").innerHTML = html;
}

function findingRow(f) {
  const [o, c] = diff(f.original, f.current);
  const loc = f.type === "inserted" || f.type === "unrecorded"
    ? `${esc(f.source)} · now line ${f.current_line}`
    : `${esc(f.source)} · line ${f.line}${f.current_line && f.current_line !== f.line ? ` (now ${f.current_line})` : ""}`;
  const content = f.type === "modified"
    ? `<div class="cell-block"><span class="cell-label">Witnessed</span><span class="diff">${o}</span></div><div class="cell-block"><span class="cell-label">On server now</span><span class="diff">${c}</span></div>`
    : f.type === "deleted" || f.type === "file_missing"
      ? `<div class="cell-block"><span class="cell-label">Witnessed, now missing from server</span><span class="diff"><del>${esc(f.original)}</del></span></div>`
      : `<div class="cell-block"><span class="cell-label">${f.type === "inserted" ? "Never witnessed: inserted later" : "Newer than the last witnessed entry"}</span><span class="diff"><ins>${esc(f.current)}</ins></span></div>`;
  const p = f.proof;
  const anchor = p ? `batch ${p.batch_id}<br>${p.explorer ? `<a href="${esc(p.explorer)}" target="_blank">${short(p.tx_hash, 8)}</a>` : `<span class="mono">${short(p.tx_hash, 8)}</span>`}` : (f.seq != null ? "awaiting anchor" : "—");
  const proof = p ? (f.proof_verified ? `<span class="proof-ok">✓ verified</span>` : `<span class="proof-bad">✗ failed</span>`) : (f.seq != null ? `<span class="proof-pending">witness only</span>` : "—");
  return `<tr><td><span class="badge b-${esc(f.type)}">${esc(f.type.replace("_", " "))}</span></td><td class="mono">${loc}</td>
    <td class="content">${content}</td><td class="mono">${f.recorded_at ? fmtTime(f.recorded_at) : "—"}</td><td class="mono">${anchor}</td><td>${proof}</td></tr>`;
}

function batchTable(batches) {
  if (!batches || !batches.length) return "";
  return `<div class="panel result-panel"><div class="panel-head"><h2>Batches checked against the blockchain</h2></div>
    <div class="table-wrap" style="max-height:340px"><table class="tbl"><thead><tr><th>Batch</th><th>Entries</th><th>Merkle root (witness)</th><th>Transaction</th><th>Result</th></tr></thead><tbody>
    ${batches.slice().reverse().map((b) => `<tr><td class="mono">${b.id}</td><td class="mono">#${b.first_seq}–#${b.last_seq} (${b.count})</td>
      <td class="mono">${short(b.root, 14)}</td><td class="mono">${b.explorer ? `<a href="${esc(b.explorer)}" target="_blank">${short(b.tx_hash, 10)}</a>` : short(b.tx_hash, 10)}</td>
      <td>${b.status === "verified" ? `<span class="proof-ok">✓ ${esc(b.status_text)}</span>` : `<span class="proof-bad">✗ ${esc(b.status_text)}</span>`}</td></tr>`).join("")}
    </tbody></table></div></div>`;
}

/* ---------------------------------------------------------------- chain */
async function loadChain() {
  const [c, bs] = await Promise.all([api("/api/v1/chain"), api("/api/v1/batches?limit=100")]);
  $("#chainMode").textContent = c.mode === "quai" ? "Quai Orchard testnet" : "Local EVM · Quai-ready";
  const kv = [
    ["Network", c.label],
    ["Status", c.connected ? (c.contract_ok ? "Connected, contract live" : "Connected, contract missing") : `Offline${c.error ? ` (${c.error})` : ""}`],
    ["Chain ID", c.chain_id ?? "—"],
    ["Latest block", c.block != null ? `#${num(c.block)}` : "—"],
    ["Contract", c.contract || "not deployed"],
    ["Writer (batcher)", c.writer || "—"],
    ["Anchors on-chain", c.anchor_count ?? "—"],
    ["RPC", c.rpc || "—"],
  ];
  if (c.zone) kv.push(["Zone", c.zone]);
  if (c.balance) kv.push(["Balance", `${c.balance} QUAI`]);
  $("#chainKv").innerHTML = kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  const link = $("#explorerLink");
  if (c.explorer_contract) { link.href = c.explorer_contract; link.classList.remove("hidden"); } else link.classList.add("hidden");
  $("#batchBody").innerHTML = bs.length ? bs.map((b) => `<tr>
    <td class="mono">${b.id}</td><td>${esc(b.agent_id)}</td><td class="mono">${num(b.count)}</td><td class="mono">#${b.first_seq}–#${b.last_seq}</td>
    <td><span class="badge ${b.reason ? "b-critical" : "b-log"}">${REASONS[b.reason]}</span></td>
    <td class="mono">${short(b.root, 12)}</td>
    <td class="mono">${b.explorer ? `<a href="${esc(b.explorer)}" target="_blank">${short(b.tx_hash, 10)}</a>` : short(b.tx_hash, 10)}</td>
    <td class="mono">${b.block_number ?? "—"}</td><td class="mono">${fmtTime(b.created_at)}</td>
    <td id="bchk-${b.id}" class="proof-pending">not checked</td></tr>`).join("")
    : `<tr><td colspan="10" class="empty">No batches yet.</td></tr>`;
}
$("#btnAnchorNow").addEventListener("click", async () => {
  await api("/api/v1/anchor-now", { method: "POST" });
  toast("Anchoring requested");
  setTimeout(loadChain, 1500);
});
$("#btnVerifyChain").addEventListener("click", async () => {
  $("#batchVerifyNote").textContent = "verifying…";
  const r = await api("/api/v1/audit/history");
  let ok = 0;
  for (const b of r.batches) {
    const cell = document.getElementById(`bchk-${b.id}`);
    if (b.status === "verified") ok++;
    if (cell) {
      cell.className = b.status === "verified" ? "proof-ok" : "proof-bad";
      cell.textContent = b.status === "verified" ? "✓ root matches" : `✗ ${b.status_text}`;
    }
  }
  $("#batchVerifyNote").textContent = `${ok}/${r.batches.length} batches match the contract · verdict ${r.verdict}`;
});

/* ---------------------------------------------------------------- compliance */
function hms(s) {
  if (s <= 0) return "overdue";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = Math.floor(s % 60);
  return `${h}h ${String(m).padStart(2, "0")}m ${String(x).padStart(2, "0")}s`;
}
let compData = null;
async function loadCompliance() {
  compData = await api("/api/v1/compliance");
  const c = compData;
  $("#retention").innerHTML = c.agents.length ? c.agents.map((a) => {
    const pct = Math.min(100, (a.days_held / c.retention_days_required) * 100);
    return `<div class="ret"><div class="ret-top"><b>${esc(a.agent_id)}</b><span class="muted" style="margin:0">logs since ${fmtDateTime(a.first_entry)}</span></div>
      <div class="bar"><i style="width:${pct}%"></i></div>
      <div class="ret-top"><span class="muted" style="margin:0">${a.days_held.toFixed(2)} of ${c.retention_days_required} days held · policy keeps ${c.retention_policy_days} days</span>
      <span class="mono">${num(a.entries)} entries · ${num(a.anchored)} anchored</span></div></div>`;
  }).join("") : `<p class="muted">No monitored servers yet.</p>`;
  $("#controls").innerHTML = c.controls.map((x) => `<li><span class="st st-${esc(x.status)}">${esc(x.status)}</span><div><div>${esc(x.name)}</div><div class="ev">${esc(x.evidence)}</div></div></li>`).join("");
  renderIncidents();
}
function renderIncidents() {
  if (!compData) return;
  const now = Date.now() / 1000;
  $("#incidentBody").innerHTML = compData.incidents.length ? compData.incidents.map((i) => `<tr>
    <td class="mono">${fmtDateTime(i.ts)}</td><td>${esc(i.title)}</td><td>${esc(i.agent_id || "witness")}</td>
    <td class="mono">${fmtDateTime(i.deadline)}</td><td class="countdown">${hms(i.deadline - now)}</td>
    <td class="mono">${i.anchor_tx ? (i.anchor_explorer ? `<a href="${esc(i.anchor_explorer)}" target="_blank">${short(i.anchor_tx, 8)}</a>` : short(i.anchor_tx, 8)) : "anchoring…"}</td></tr>`).join("")
    : `<tr><td colspan="6" class="empty">No critical incidents.</td></tr>`;
}

/* ---------------------------------------------------------------- loop */
setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString([], { hour12: false }); renderIncidents(); }, 1000);
setInterval(refresh, 1000);
setInterval(() => { if (view === "compliance") loadCompliance(); }, 5000);
refresh().then(() => {
  const h = location.hash.replace("#", "");
  if (["monitor", "auditor", "chain", "compliance"].includes(h)) show(h);
});
