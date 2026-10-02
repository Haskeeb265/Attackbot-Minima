/* Attackbot UI — vanilla JS, no build step, no dependencies.
 *
 * One poll loop, one state object. Panels are views over state; the only
 * timers are the pollers the user can see (live dot, follow, job output).
 */
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

const state = {
  programs: [],
  engineRuns: [],
  reconTargets: [],
  program: null,
  engineRun: null,
  reconTarget: null,
  engineCursor: 0,
  engineRows: [],
  following: false,
  jobTimer: null,
  jobView: null,
};

// ------------------------------------------------------------------ //
// api
// ------------------------------------------------------------------ //

async function api(path) {
  const res = await fetch(path);
  const body = await res.json().catch(() => ({ error: "unreadable response" }));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

async function post(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => ({ error: "unreadable response" }));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

// ------------------------------------------------------------------ //
// panels
// ------------------------------------------------------------------ //

function showPanel(name) {
  for (const btn of document.querySelectorAll("nav button")) {
    btn.classList.toggle("active", btn.dataset.panel === name);
  }
  for (const section of document.querySelectorAll(".panel")) {
    section.classList.toggle("active", section.id === `panel-${name}`);
  }
  if (name === "program") loadProgram();
  if (name === "recon") loadReconLogs();
  if (name === "graph") loadGraph();
  if (name === "inputs") loadInputs();
  if (name === "engine") { renderEngineLog(); if (state.following) pollEngineLog(); }
  if (name === "output") loadOutput();
  if (name === "run") renderJobs();
}

// ------------------------------------------------------------------ //
// 1. program
// ------------------------------------------------------------------ //

async function loadState() {
  try {
    const data = await api("/api/state");
    state.programs = data.programs || [];
    state.engineRuns = data.engine_runs || [];
    state.reconTargets = data.recon_targets || [];
    fillSelect($("program-handle"), state.programs.map((p) => p.handle),
      state.program ? state.program.handle : null);
    fillSelect($("engine-run-select"), state.engineRuns.map((r) => r.run), state.engineRun);
    fillSelect($("recon-target-select"), state.reconTargets, state.reconTarget);
    setLive(true, `polling · ${state.programs.length} programs · ${state.engineRuns.length} engine runs`);
    renderJobsIfVisible();
  } catch (err) {
    setLive(false, err.message);
  }
}

function fillSelect(sel, values, selected) {
  if (!sel) return;
  const current = selected ?? sel.value;
  sel.innerHTML = "";
  for (const value of values) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = value;
    sel.appendChild(opt);
  }
  if (current && values.includes(current)) sel.value = current;
}

function setLive(ok, label) {
  const el = $("live-indicator");
  el.classList.toggle("on", !!ok);
  $("live-label").textContent = label;
}

async function loadProgram() {
  const handle = $("program-handle").value;
  if (!handle) return;
  const body = $("program-body");
  body.innerHTML = '<span class="muted">loading…</span>';
  try {
    const p = await api(`/api/program?handle=${encodeURIComponent(handle)}`);
    state.program = p;
    body.innerHTML = renderProgram(p);
  } catch (err) {
    body.innerHTML = `<span class="error-text">${esc(err.message)}</span>`;
  }
}

function renderProgram(p) {
  const kv = (k, v) => v ? `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>` : "";
  const flags = [];
  if (p.offers_bounties) flags.push("<span class='badge in-scope'>bounties</span>");
  if (p.open_scope) flags.push("<span class='badge'>open scope</span>");
  if (p.gold_standard_safe_harbor) flags.push("<span class='badge in-scope'>gold-standard safe harbor</span>");
  const scopeRow = (row, cls) => `
    <tr>
      <td><span class="badge ${cls}">${esc(row.type || "?")}</span></td>
      <td>${esc(row.identifier)}</td>
      <td class="muted small">${esc(row.max_severity || "")}</td>
      <td class="muted small">${esc(row.eligible_for_bounty === false ? "not eligible for bounty" : "")}</td>
      <td class="muted small">${esc(row.instructions || "")}</td>
    </tr>`;
  return `
    <div class="card">
      <h2 style="border:none;margin-bottom:4px;">${esc(p.program_name || p.handle)}
        <span class="badge">${esc(p.handle)}</span>
        ${p.status ? `<span class="badge in-scope">${esc(p.status)}</span>` : ""}
        ${p.platform ? `<span class="badge">${esc(p.platform)}</span>` : ""}
        ${flags.join("")}
      </h2>
      <div class="kv">
        ${kv("program url", p.program_url)}
        ${kv("description", p.description)}
        ${kv("policy", p.policy)}
        ${kv("disclosure", p.disclosure_policy)}
        ${kv("safe harbor", p.safe_harbor)}
      </div>
    </div>
    <div class="statgrid">
      <div class="stat good"><div class="num">${p.counts.in_scope}</div><div class="lbl">in scope</div></div>
      <div class="stat bad"><div class="num">${p.counts.out_of_scope}</div><div class="lbl">out of scope</div></div>
      <div class="stat"><div class="num">${p.counts.unsupported}</div><div class="lbl">non-asset types</div></div>
      <div class="stat"><div class="num">${p.counts.exclusions}</div><div class="lbl">exclusions</div></div>
      <div class="stat"><div class="num">${p.counts.weaknesses}</div><div class="lbl">weakness classes</div></div>
    </div>
    <h3>In scope (${p.counts.in_scope})</h3>
    <table><thead><tr><th>type</th><th>identifier</th><th>max severity</th><th>bounty</th><th>instructions</th></tr></thead>
    <tbody>${p.in_scope.map((r) => scopeRow(r, "in-scope")).join("")}</tbody></table>
    <h3>Out of scope — the boundary the gate enforces (${p.counts.out_of_scope})</h3>
    <table><thead><tr><th>type</th><th>identifier</th><th>max severity</th><th>bounty</th><th>instructions</th></tr></thead>
    <tbody>${p.out_of_scope.map((r) => scopeRow(r, "out-of-scope")).join("")}</tbody></table>
    ${p.unsupported.length ? `
      <h3>Declared non-asset types (${p.unsupported.length})</h3>
      <table><thead><tr><th>type</th><th>identifier</th></tr></thead>
      <tbody>${p.unsupported.map((r) => `<tr><td><span class="badge unsupported">${esc(r.type)}</span></td><td>${esc(r.identifier)}</td></tr>`).join("")}</tbody></table>` : ""}
    ${p.exclusions.length ? `
      <h3>Exclusions (${p.exclusions.length})</h3>
      <table><thead><tr><th>category</th><th>details</th></tr></thead>
      <tbody>${p.exclusions.map((e) => `<tr><td>${esc(e.category)}</td><td class="muted small">${esc(e.details)}</td></tr>`).join("")}</tbody></table>` : ""}
    ${p.weaknesses.length ? `
      <h3>Weakness classes (${p.weaknesses.length})</h3>
      <table><thead><tr><th>id</th><th>name</th></tr></thead>
      <tbody>${p.weaknesses.map((w) => `<tr><td class="muted small">${esc(w.id)}</td><td>${esc(w.name)}</td></tr>`).join("")}</tbody></table>` : ""}
  `;
}

// ------------------------------------------------------------------ //
// 2. recon logs
// ------------------------------------------------------------------ //

async function loadReconLogs() {
  const target = $("recon-target-select").value;
  if (!target) return;
  $("recon-status").textContent = `loading ${target}…`;
  try {
    const data = await api(`/api/recon/logs?target=${encodeURIComponent(target)}&limit=400`);
    const box = $("recon-logs");
    if (!data.logs.length) {
      box.innerHTML = `<span class="muted">no recon logs for ${esc(target)} — run one from the Run panel</span>`;
      $("recon-status").textContent = "";
      return;
    }
    box.innerHTML = data.logs.map((log) =>
      `<div class="stagehead">${esc(log.stage)} · ${esc(log.file)} · ${log.lines} lines</div>` +
      esc(log.text)
    ).join("\n");
    $("recon-status").textContent = `${data.logs.length} stage log(s)`;
  } catch (err) {
    $("recon-status").textContent = err.message;
  }
}

// ------------------------------------------------------------------ //
// 3. graph
// ------------------------------------------------------------------ //

const KIND_COLORS = {
  domain: "#58a6ff", host: "#3fb950", ip: "#d29922", port: "#f0883e",
  service: "#f0883e", url: "#bc8cff", param: "#f85149", endpoint: "#f85149",
  asn: "#79c0ff", cidr: "#79c0ff", bucket: "#56d364", program: "#e3b341",
  scope: "#e3b341", weakness: "#ff7b72", js: "#a5d6ff", sourcemap: "#a5d6ff",
  default: "#8b949e",
};
const kindColor = (k) => KIND_COLORS[(k || "").toLowerCase()] || KIND_COLORS.default;

async function loadGraph() {
  const target = $("recon-target-select").value || "";
  const q = $("graph-query").value.trim();
  const kind = $("graph-kind").value;
  const cap = Math.max(10, Math.min(500, parseInt($("graph-cap").value, 10) || 120));
  $("graph-status").textContent = "loading…";
  try {
    const params = new URLSearchParams({ cap: String(cap) });
    if (target) params.set("target", target);
    if (q) params.set("q", q);
    if (kind) params.set("kind", kind);
    const g = await api(`/api/recon/graph?${params}`);
    renderGraph(g);
  } catch (err) {
    $("graph-status").textContent = err.message;
  }
}

function renderGraph(g) {
  const svg = $("graph-svg");
  const detail = $("node-detail");
  detail.style.display = "none";
  if (!g.available) {
    $("graph-summary").innerHTML = `<span class="error-text">${esc(g.reason)}</span>`;
    svg.innerHTML = "";
    return;
  }
  const integ = g.integrity || {};
  $("graph-summary").innerHTML = `
    <div class="statgrid">
      <div class="stat"><div class="num">${g.counts.nodes}</div><div class="lbl">nodes</div></div>
      <div class="stat"><div class="num">${g.counts.edges}</div><div class="lbl">edges</div></div>
      <div class="stat good"><div class="num">${g.by_scope.in_scope || 0}</div><div class="lbl">in scope</div></div>
      <div class="stat bad"><div class="num">${g.by_scope.out_of_scope || 0}</div><div class="lbl">out of scope</div></div>
      <div class="stat"><div class="num">${g.by_scope.needs_review || 0}</div><div class="lbl">needs review</div></div>
      <div class="stat"><div class="num">${g.counts.shown_nodes}</div><div class="lbl">drawn (top-scored)</div></div>
    </div>
    <span class="muted small">generated ${esc(g.generated_at || "?")} · consistent: ${esc(integ.consistent)} · target ${esc(g.target || "?")}</span>`;
  $("graph-kind").innerHTML =
    '<option value="">all kinds</option>' +
    Object.entries(g.by_kind).map(([k, n]) =>
      `<option value="${esc(k)}">${esc(k)} (${n})</option>`).join("");

  // force layout
  const nodes = g.nodes;
  const edges = g.edges;
  const W = svg.clientWidth || 1100, H = 560;
  const index = new Map(nodes.map((n, i) => [n.id, i]));
  nodes.forEach((n, i) => { n.x = W / 2; n.y = H / 2; });
  const deg = new Map(nodes.map((n) => [n.id, 0]));
  edges.forEach((e) => {
    if (index.has(e.source) && index.has(e.target)) {
      deg.set(e.source, deg.get(e.source) + 1);
      deg.set(e.target, deg.get(e.target) + 1);
    }
  });
  for (let iter = 0; iter < 300; iter++) {
    // repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy || 1;
        const f = 1200 / d2;
        const d = Math.sqrt(d2);
        dx /= d; dy /= d;
        a.x += dx * f; a.y += dy * f;
        b.x -= dx * f; b.y -= dy * f;
      }
    }
    // springs
    for (const e of edges) {
      const a = nodes[index.get(e.source)], b = nodes[index.get(e.target)];
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d - 60) * 0.02;
      a.x += (dx / d) * f; a.y += (dy / d) * f;
      b.x -= (dx / d) * f; b.y -= (dy / d) * f;
    }
    // centering
    for (const n of nodes) {
      n.x += (W / 2 - n.x) * 0.01;
      n.y += (H / 2 - n.y) * 0.01;
      n.x = Math.max(24, Math.min(W - 24, n.x));
      n.y = Math.max(24, Math.min(H - 24, n.y));
    }
  }
  const radius = (n) => 4 + Math.min(8, Math.sqrt(Math.max(0, deg.get(n.id) || 0)) * 2);
  const edgeMarkup = edges.map((e) => {
    const a = nodes[index.get(e.source)], b = nodes[index.get(e.target)];
    if (!a || !b) return "";
    return `<line class="edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}">
      <title>${esc(e.relationship || e.type || "")}</title></line>`;
  }).join("");
  const nodeMarkup = nodes.map((n) => {
    const r = radius(n);
    const label = String(n.identity || n.id || "").slice(0, 26);
    return `<g class="node" data-id="${esc(n.id)}">
      <circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${kindColor(n.kind)}"
        stroke="${n.scope_state === "out_of_scope" ? "#f85149" : n.scope_state === "in_scope" ? "#3fb950" : "#0a0d12"}"
        stroke-width="${n.scope_state ? 2 : 1.5}">
        <title>${esc(n.id)} · score ${esc(n.score ?? "—")} · ${esc(n.band || "")} · ${esc(n.trust || "")}</title>
      </circle>
      <text x="${n.x + r + 3}" y="${n.y + 3}">${esc(label)}</text>
    </g>`;
  }).join("");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.innerHTML = edgeMarkup + nodeMarkup;
  $("graph-status").textContent = `${nodes.length} nodes · ${edges.length} edges drawn`;
  svg.querySelectorAll(".node").forEach((el) => {
    el.addEventListener("click", () => {
      const n = nodes.find((x) => x.id === el.dataset.id);
      if (!n) return;
      detail.innerHTML = `
        <h3 style="margin-top:0;">${esc(n.kind)}</h3>
        <div class="kv">
          <div class="k">identity</div><div class="v">${esc(n.identity)}</div>
          <div class="k">id</div><div class="v small">${esc(n.id)}</div>
          <div class="k">score</div><div class="v">${esc(n.score ?? "unscored")} ${esc(n.band || "")}</div>
          <div class="k">trust</div><div class="v">${esc(n.trust)}</div>
          <div class="k">evidence</div><div class="v">${esc(n.evidence_state || "—")}</div>
          <div class="k">scope</div><div class="v">${esc(n.scope_state || "—")} ${esc(n.scope_reason || "")}</div>
        </div>`;
      detail.style.display = "block";
    });
  });
  $("graph-legend").innerHTML = Object.entries(KIND_COLORS)
    .filter(([k]) => k !== "default")
    .map(([k, c]) => `<span><span class="swatch" style="background:${c}"></span>${esc(k)}</span>`)
    .join("");
}

// ------------------------------------------------------------------ //
// 4. engine inputs
// ------------------------------------------------------------------ //

async function loadInputs() {
  const run = $("engine-run-select").value;
  const body = $("inputs-body");
  if (!run) return;
  body.innerHTML = '<span class="muted">loading…</span>';
  try {
    const data = await api(`/api/engine/inputs?run=${encodeURIComponent(run)}`);
    if (!data.available) {
      body.innerHTML = `<span class="muted">${esc(data.reason)}</span>`;
      return;
    }
    const surf = (s) => `
      <tr>
        <td>${esc(s.url)}</td>
        <td>${esc(s.param || "")}</td>
        <td>${esc(s.where || "")}</td>
        <td><span class="badge">${esc(s.capability || "")}</span></td>
        <td class="muted small">${esc(s.label || "")}</td>
      </tr>`;
    body.innerHTML = `
      <div class="statgrid">
        <div class="stat"><div class="num">${(data.surfaces || []).length}</div><div class="lbl">seed surfaces</div></div>
        <div class="stat"><div class="num">${(data.techniques || []).length}</div><div class="lbl">techniques</div></div>
        <div class="stat"><div class="num">${data.junction_candidates || 0}</div><div class="lbl">junction candidates</div></div>
      </div>
      <div class="grid2">
        <div>
          <h3>Surfaces that entered the engine</h3>
          <table><thead><tr><th>url</th><th>param</th><th>where</th><th>capability</th><th>label</th></tr></thead>
          <tbody>${(data.surfaces || []).map(surf).join("")}</tbody></table>
          <h3>Scheduler picks</h3>
          ${(data.scheduler_picks || []).map((p) =>
            `<div class="card"><span class="badge">${esc(p.technique)}</span> ${esc(p.surface || "")}
             <div class="muted small">${esc(p.reason || "")}</div></div>`).join("") || '<span class="muted">none logged</span>'}
        </div>
        <div>
          <h3>Hypotheses (${(data.hypotheses || []).length})</h3>
          ${(data.hypotheses || []).map((h) => `
            <div class="card">
              <div>${esc(h.claim)}</div>
              <div class="muted small">id: ${esc(h.id)} · rests on: ${esc(h.rests_on)}</div>
            </div>`).join("") || '<span class="muted">none logged</span>'}
          <h3>Transport capabilities</h3>
          <div id="capabilities"></div>
        </div>
      </div>`;
    const caps = data.capabilities || {};
    $("capabilities").innerHTML = Object.entries(caps).map(([name, cap]) => `
      <div class="kv" style="margin-bottom:8px;">
        <div class="k">${esc(name)}</div>
        <div class="v ${cap.available ? "ok-text" : "error-text"}">${cap.available ? "available" : "unavailable"} ${esc(cap.reason || "")}</div>
      </div>`).join("");
  } catch (err) {
    body.innerHTML = `<span class="error-text">${esc(err.message)}</span>`;
  }
}

// ------------------------------------------------------------------ //
// 5. engine log (realtime tail)
// ------------------------------------------------------------------ //

function fmtTime(at) {
  if (!at) return "";
  const d = new Date(at * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(Math.floor((at % 1) * 1000)).padStart(3, "0");
}

async function pollEngineLog() {
  const run = $("engine-run-select").value;
  if (!run) return;
  try {
    const data = await api(`/api/engine/log?run=${encodeURIComponent(run)}&cursor=${state.engineCursor}&limit=500`);
    if (data.rows.length) {
      state.engineRows.push(...data.rows);
      if (state.engineRows.length > 4000) state.engineRows = state.engineRows.slice(-3000);
      state.engineCursor = data.next_index;
      renderEngineLog();
    }
    const overview = await api(`/api/engine/overview?run=${encodeURIComponent(run)}`);
    renderEngineOverview(overview);
    setLive(true, `following ${run} · ${overview.rows} rows`);
  } catch (err) {
    setLive(false, err.message);
  }
}

let overviewCache = null;
function renderEngineOverview(overview) {
  if (overview) overviewCache = overview;
  const o = overviewCache;
  if (!o) return;
  $("engine-overview").innerHTML = `
    <div class="stat"><div class="num">${o.rows}</div><div class="lbl">log rows</div></div>
    <div class="stat good"><div class="num">${o.findings}</div><div class="lbl">findings</div></div>
    <div class="stat"><div class="num">${o.candidates}</div><div class="lbl">candidates</div></div>
    <div class="stat good"><div class="num">${o.gate.ALLOW}</div><div class="lbl">gate allow</div></div>
    <div class="stat bad"><div class="num">${o.gate.DENY}</div><div class="lbl">gate deny</div></div>
    <div class="stat"><div class="num">${o.gate.DEFER}</div><div class="lbl">gate defer</div></div>`;
}

function renderEngineLog() {
  const box = $("engine-log");
  const wantVerdicts = $("engine-filter-verdicts").checked;
  const wantGate = $("engine-filter-gate").checked;
  let rows = state.engineRows;
  if (wantVerdicts) rows = rows.filter((r) =>
    ["verdict", "candidate", "candidate.junction", "receipt", "run.begin", "run.end", "scheduler.pick"].includes(r.type));
  if (wantGate) rows = rows.filter((r) => r.type === "gate.decision");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
  box.innerHTML = rows.map(renderRow).join("");
  if (state.following || atBottom) box.scrollTop = box.scrollHeight;
  $("engine-status").textContent = `${rows.length} row(s) shown`;
}

function renderRow(row) {
  const type = esc(row.type);
  const classes = ["wrow", `type-${type.replace(".", "\\.")}`];
  if (row.type === "verdict") classes.push(row.proven ? "proven-true" : "proven-false");
  if (row.type === "gate.decision") classes.push(`decision-${String(row.verb || "").toLowerCase()}`);
  let body = "";
  if (row.type === "gate.decision") {
    body = `<span class="badge ${String(row.verb).toLowerCase()}">${esc(row.verb)}</span> ${esc(row.host)} · ${esc(row.kind)} · ${esc(row.technique || "")} · ${esc(row.reason || "")}`;
  } else if (row.type === "effect.request") {
    body = `→ ${esc(row.kind)} ${esc(row.technique || "")} ${esc((row.detail || {}).url || row.operation || "")}`;
  } else if (row.type === "effect.result") {
    body = `← ${esc(row.kind)} status ${esc(row.status ?? "—")} ${esc(row.bytes ? row.bytes + "B" : "")} ${esc(row.elapsed != null ? row.elapsed + "s" : "")} ${esc(row.error || "")}`;
  } else if (row.type === "observation") {
    body = `${esc(row.kind)} ${esc(JSON.stringify(row.payload || {}).slice(0, 240))}`;
  } else if (row.type === "note") {
    body = `[${esc(row.stage || "")}] ${esc(row.reason || (row.hypothesis || {}).claim || JSON.stringify(row).slice(0, 200))}`;
  } else if (row.type === "candidate" || row.type === "candidate.junction") {
    body = `<b>${esc(row.vuln_class || "")}</b> ${esc(row.summary || "")}<br>
      payload: <code>${esc(row.payload || "")}</code><br>
      repro: <code>${esc(row.repro_url || "")}</code>`;
  } else if (row.type === "verdict") {
    body = `${row.proven ? '<span class="badge proven">PROVEN</span>' : '<span class="badge refused">REFUSED</span>'}
      grade ${esc(row.grade || "")} · ${esc(row.candidate || "")}<br>${esc(row.reason || "")}`;
  } else if (row.type === "receipt") {
    body = `${esc(row.arm)} → ${esc(row.outcome)}${row.conclusive ? " (conclusive)" : ""}`;
  } else if (row.type === "run.begin") {
    body = `target ${esc(row.target)} · techniques ${(row.techniques || []).join(", ")}`;
  } else if (row.type === "run.end") {
    body = esc(JSON.stringify(row.counts || {}));
  } else if (row.type === "scheduler.pick") {
    body = `${esc(row.technique)} on ${esc(row.surface || "")} — ${esc(row.reason || "")}`;
  } else if (row.type === "llm.junction") {
    body = `${esc(row.junction || "")} ${row.degraded ? "degraded" : "live"} ${esc(JSON.stringify(row).slice(0, 200))}`;
  } else {
    body = esc(JSON.stringify(row).slice(0, 240));
  }
  return `<div class="${classes.join(" ")}">
    <div class="whead"><span class="wtype">${type}</span><span class="wat">${fmtTime(row.at)}</span></div>
    <div class="wbody">${body}</div>
  </div>`;
}

// ------------------------------------------------------------------ //
// 6. engine output
// ------------------------------------------------------------------ //

async function loadOutput() {
  const run = $("engine-run-select").value;
  const body = $("output-body");
  if (!run) return;
  body.innerHTML = '<span class="muted">loading…</span>';
  try {
    const data = await api(`/api/engine/report?run=${encodeURIComponent(run)}`);
    if (!data.available) {
      body.innerHTML = `<span class="muted">${esc(data.reason)}</span>`;
      return;
    }
    const r = data.report;
    const findings = r.findings || [];
    const sourceNote = data.source === "world_log"
      ? '<span class="muted small">derived from the world log (a campaign run writes no report.json)</span>'
      : "";
    body.innerHTML = `
      <div class="statgrid">
        <div class="stat good"><div class="num">${findings.length}</div><div class="lbl">findings</div></div>
        ${sourceNote}
        <div class="stat"><div class="num">${(r.leads || []).length}</div><div class="lbl">leads</div></div>
        <div class="stat"><div class="num">${(r.gate || {}).decisions ?? 0}</div><div class="lbl">gate decisions</div></div>
        <div class="stat bad"><div class="num">${(r.gate || {}).out_of_scope_requests ?? 0}</div><div class="lbl">out-of-scope requests</div></div>
      </div>
      ${(findings.length ? findings.map((f) => `
        <div class="finding">
          <b>${esc(f.vuln_class || "?")}</b> — grade ${esc(f.grade || "?")}
          <div>${esc(f.summary || "")}</div>
          ${f.repro_url ? `<div class="small">repro: <code>${esc(f.repro_url)}</code></div>` : ""}
          ${f.eligibility ? `<div class="small">eligibility: ${esc(f.eligibility)} (${esc(f.eligibility_reason || "")})</div>` : ""}
        </div>`).join("") : '<div class="muted card">No findings in this run.</div>')}
      <h3>Gate</h3>
      <div class="kv">
        <div class="k">decisions</div><div class="v">${esc(JSON.stringify((r.gate || {}).by_verb || {}))}</div>
        <div class="k">uncleared effects</div><div class="v">${esc((r.gate || {}).uncleared_effects ?? 0)}</div>
      </div>
      <h3>Report lines</h3>
      <div class="logbox">${esc((r.report_lines || []).join("\n"))}</div>
      <h3>Counts</h3>
      <div class="logbox">${esc(JSON.stringify(r.counts || {}, null, 2))}</div>`;
  } catch (err) {
    body.innerHTML = `<span class="error-text">${esc(err.message)}</span>`;
  }
}

// ------------------------------------------------------------------ //
// jobs
// ------------------------------------------------------------------ //

async function startJob(kind, params) {
  try {
    const data = await post("/api/run", { kind, params });
    state.jobView = data.job.id;
    renderJobs();
    showPanel("run");
    startJobOutputPolling();
  } catch (err) {
    alert(err.message);
  }
}

function startJobOutputPolling() {
  if (state.jobTimer) clearInterval(state.jobTimer);
  state.jobTimer = setInterval(pollJobOutput, 700);
  pollJobOutput();
}

async function pollJobOutput() {
  if (!state.jobView) return;
  try {
    const data = await api(`/api/jobs/output?id=${encodeURIComponent(state.jobView)}&limit=2000`);
    const box = $("jobs-output");
    if (!box) return;
    if (data.error) { box.textContent = data.error; return; }
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
    box.textContent = data.lines.join("\n");
    if (atBottom) box.scrollTop = box.scrollHeight;
    const status = data.status === "running" ? "running…" : `${data.status} (exit ${data.exit_code})`;
    const el = $("jobs-status");
    if (el) el.textContent = status;
    if (data.status !== "running") { /* keep polling cheaply; timer cleared on new job */ }
  } catch (err) { /* transient */ }
}

function renderJobsIfVisible() {
  if (document.getElementById("panel-run").classList.contains("active")) renderJobs();
}

function renderJobs() {
  const body = $("jobs-body");
  const jobsList = window.__jobs || [];
  if (!jobsList.length) { body.innerHTML = '<span class="muted">No jobs started this session.</span>'; return; }
  const active = jobsList.find((j) => j.id === state.jobView);
  const jobLabel = active ? `${active.label} · ${active.status}` : (state.jobView || "");
  body.innerHTML = `
    <div class="card">
      <div style="display:flex;gap:10px;align-items:center;">
        <span class="badge">${esc(jobLabel)}</span>
        <span id="jobs-status" class="muted small"></span>
        <button class="btn danger" id="jobs-stop" style="margin-left:auto;">Stop</button>
      </div>
      <div id="jobs-output" class="logbox" style="max-height:420px;"></div>
    </div>`;
  $("jobs-stop").addEventListener("click", async () => {
    if (state.jobView) await post("/api/jobs/stop", { id: state.jobView });
  });
}

// ------------------------------------------------------------------ //
// wiring
// ------------------------------------------------------------------ //

function syncJobs() {
  return api("/api/jobs").then((data) => { window.__jobs = data.jobs || []; renderJobsIfVisible(); }).catch(() => {});
}

for (const btn of document.querySelectorAll("nav button")) {
  btn.addEventListener("click", () => showPanel(btn.dataset.panel));
}
$("program-handle").addEventListener("change", loadProgram);
$("program-reload").addEventListener("click", loadProgram);
$("recon-target-select").addEventListener("change", () => {
  if (document.getElementById("panel-recon").classList.contains("active")) loadReconLogs();
  if (document.getElementById("panel-graph").classList.contains("active")) loadGraph();
});
$("recon-refresh").addEventListener("click", loadReconLogs);
$("graph-reload").addEventListener("click", loadGraph);
$("graph-query").addEventListener("keydown", (e) => { if (e.key === "Enter") loadGraph(); });
$("engine-run-select").addEventListener("change", () => {
  state.engineCursor = 0;
  state.engineRows = [];
  state.engineRun = $("engine-run-select").value;
  renderEngineLog();
  renderEngineOverview(null);
  if (document.getElementById("panel-engine").classList.contains("active")) pollEngineLog();
  if (document.getElementById("panel-inputs").classList.contains("active")) loadInputs();
  if (document.getElementById("panel-output").classList.contains("active")) loadOutput();
});
$("engine-filter-verdicts").addEventListener("change", renderEngineLog);
$("engine-filter-gate").addEventListener("change", renderEngineLog);
$("engine-follow").addEventListener("click", () => {
  state.following = !state.following;
  $("engine-follow").textContent = `Follow: ${state.following ? "on" : "off"}`;
  $("engine-follow").classList.toggle("primary", state.following);
  if (state.following) {
    pollEngineLog();
    state.followTimer = setInterval(pollEngineLog, 1200);
  } else if (state.followTimer) {
    clearInterval(state.followTimer);
    state.followTimer = null;
  }
});

$("run-recon-btn").addEventListener("click", () => startJob("recon", {
  target: $("run-recon-target").value.trim(),
  until_converged: $("run-recon-converged").checked,
  skip_subdomain: $("run-recon-skip-sub").checked,
  skip_ports: $("run-recon-skip-ports").checked,
  skip_url: $("run-recon-skip-url").checked,
}));
$("run-engine-btn").addEventListener("click", () => startJob("engine", {
  target: $("run-engine-target").value.trim(),
  surfaces: $("run-engine-surface").value.split("\n").map((s) => s.trim()).filter(Boolean),
  cookies: [$("run-engine-cookie").value.trim()].filter(Boolean),
  session_b_cookie: $("run-engine-cookie-b").value.trim(),
  campaign: parseInt($("run-engine-campaign").value, 10) || 0,
  host_budget: parseInt($("run-engine-budget").value, 10) || 0,
  from_graph: $("run-engine-from-graph").checked,
  llm_draft: $("run-engine-llm").checked,
  hypothesize_from_recon: $("run-engine-hyp").checked,
  force: $("run-engine-force").checked,
}));
$("run-fixture-btn").addEventListener("click", () => startJob("engine_fixture", {
  campaign: parseInt($("run-engine-campaign").value, 10) || 0,
  force: $("run-engine-force").checked,
}));
$("run-demo-btn").addEventListener("click", async () => {
  // The guided flow in one click: seed the demo program, then run the
  // fixture engine into its own output dir, then land the operator on the
  // run selector with the demo run pre-selected.
  const btn = $("run-demo-btn");
  btn.disabled = true; btn.textContent = "Seeding…";
  try {
    await post("/api/demo/seed", {});
  } catch (err) { /* seeding is best-effort: no DB, panels 2-6 still work */ }
  btn.textContent = "Running…";
  startJob("engine_fixture", { campaign: 4, force: true, output_dir: "demo_flow" });
  btn.disabled = false; btn.textContent = "Run demo flow";
  // Point the run selectors at the demo run once the state poll brings it in.
  setTimeout(() => {
    const sel = $("engine-run-select");
    if ([...sel.options].some((o) => o.value === "demo_flow")) {
      sel.value = "demo_flow";
      sel.dispatchEvent(new Event("change"));
    }
  }, 3000);
});

loadState();
syncJobs();
setInterval(loadState, 5000);
showPanel("program");
