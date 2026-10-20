"use strict";

// Everything that comes from the log (addresses, user names, passwords, ...) is attacker controlled. It is only ever put into the page with textContent, never as HTML.

const REFRESH_MS = 5000;
const SVGNS = "http://www.w3.org/2000/svg";

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function svgEl(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}

const fmt = (n) => (typeof n === "number" ? n.toLocaleString() : "—");
const hhmm = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};
const when = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
};

// ── map ──────────────────────────────────────────────────────────────────────

const mapState = { ready: false, error: null, features: null, path: null, isoNumeric: null, sphere: null };
const MAP_W = 960, MAP_H = 440;

function libraryProblem() {
  if (typeof d3 === "undefined") return "d3 did not load (check that /vendor/d3.min.js is served).";
  if (typeof d3.geoNaturalEarth1 !== "function") return "The loaded d3 has no geoNaturalEarth1 (version " + (d3.version || "unknown") + "); d3 v4 or newer is needed.";
  if (typeof topojson === "undefined" || typeof topojson.feature !== "function") return "topojson-client did not load (check /vendor/topojson-client.min.js).";
  return null;
}

async function loadJson(url) {
  const r = await fetch(url, { cache: "force-cache" });
  if (!r.ok) throw new Error(url + ": HTTP " + r.status);
  return r.json();
}

async function initMap() {
  const problem = libraryProblem();
  if (problem) { mapState.error = problem; return; }
  try {
    const [topo, iso] = await Promise.all([loadJson("/vendor/countries-110m.json"), loadJson("/vendor/iso-numeric.json")]);
    const countries = topojson.feature(topo, topo.objects.countries);
    // Antarctica only wastes space; leave it out and fit the projection to the rest.
    const features = countries.features.filter((f) => Number(f.id) !== 10);
    const projection = d3.geoNaturalEarth1().fitSize([MAP_W, MAP_H], { type: "FeatureCollection", features });
    mapState.path = d3.geoPath(projection);
    mapState.features = features;
    mapState.isoNumeric = iso;
    mapState.ready = true;
  } catch (e) {
    mapState.error = "Map data could not be loaded: " + e.message;
  }
}

// Alpha-2 code of a world-atlas feature (they carry the numeric ISO id; a few have none).
function featureCode(f, numericToCode) {
  if (f.id != null && numericToCode.has(Number(f.id))) return numericToCode.get(Number(f.id));
  if (f.properties && f.properties.name === "Kosovo") return "XK";
  return null;
}

function renderMap(data) {
  const box = document.getElementById("map");
  const note = document.getElementById("mapnote");
  box.replaceChildren();
  note.textContent = "";

  if (!mapState.ready) {
    box.appendChild(el("div", "Map unavailable: " + (mapState.error || "still loading…"), "err"));
    return;
  }

  const counts = data.countries || {};
  const names = data.countryNames || {};
  const max = Math.max(1, ...Object.values(counts));
  const color = d3.scaleSequentialSqrt([0, max], d3.interpolateYlOrRd);

  const numericToCode = new Map(Object.entries(mapState.isoNumeric).map(([code, n]) => [n, code]));

  const svg = svgEl("svg", { viewBox: `0 0 ${MAP_W} ${MAP_H}`, role: "img", "aria-label": "Connections by country" });
  const drawn = new Set();

  for (const f of mapState.features) {
    const code = featureCode(f, numericToCode);
    const n = code ? counts[code] || 0 : 0;
    const p = svgEl("path", { d: mapState.path(f) || "", class: "land" + (code && code === data.myLocation ? " mine" : "") });
    p.setAttribute("fill", n > 0 ? color(n) : "#1b2a41");
    const title = svgEl("title");
    const label = (f.properties && f.properties.name) || code || "";
    title.textContent = n > 0 ? `${names[code] || label}: ${n}` : label;
    p.appendChild(title);
    svg.appendChild(p);
    if (code) drawn.add(code);
  }
  box.appendChild(svg);

  // Ranking next to the map; also shows countries that are too small for the 110m map.
  const list = document.getElementById("toplist");
  list.replaceChildren();
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  for (const [code, n] of ranked.slice(0, 12)) {
    const li = el("li");
    li.appendChild(el("span", code, "code"));
    li.appendChild(el("span", names[code] || code));
    li.appendChild(el("span", fmt(n)));
    const bar = el("div", null, "bar");
    bar.style.width = Math.max(2, Math.round((n / max) * 100)) + "%";
    li.appendChild(bar);
    list.appendChild(li);
  }
  if (!ranked.length) list.appendChild(el("li", "No located connections yet", "empty"));

  const hidden = ranked.filter(([code]) => !drawn.has(code));
  const bits = [];
  if (hidden.length) bits.push(hidden.length + " small countr" + (hidden.length === 1 ? "y is" : "ies are") + " in the list but too small for this map: " + hidden.map(([c, n]) => c + " " + n).join(", "));
  if (data.geoPending > 0) bits.push(data.geoPending + " address(es) still waiting for a country lookup");
  note.textContent = bits.join(". ");
}

// ── timeline ─────────────────────────────────────────────────────────────────

function renderTimeline(data) {
  const box = document.getElementById("timeline");
  box.replaceChildren();
  const t = data.timeline || [];
  if (!t.length) { box.appendChild(el("div", "No data", "empty")); return; }

  const W = 960, H = 200, L = 36, R = 8, T = 8, B = 22;
  const iw = W - L - R, ih = H - T - B;
  const max = Math.max(1, ...t.map((b) => Math.max(b.ssh + b.telnet, b.passwords + b.keys)));
  const y = (v) => T + ih - (v / max) * ih;
  const bw = iw / t.length;

  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Activity per minute" });
  for (const frac of [0, 0.5, 1]) {
    const v = Math.round(max * frac);
    svg.appendChild(svgEl("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: "#1f2f4a" }));
    const lab = svgEl("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end", fill: "#8aa0bf", "font-size": 11 });
    lab.textContent = String(v);
    svg.appendChild(lab);
  }
  t.forEach((b, i) => {
    const x = L + i * bw;
    const hs = (b.ssh / max) * ih, ht = (b.telnet / max) * ih;
    if (b.ssh) svg.appendChild(svgEl("rect", { x: x + 1, y: T + ih - hs, width: Math.max(1, bw - 2), height: hs, fill: "#38bdf8" }));
    if (b.telnet) svg.appendChild(svgEl("rect", { x: x + 1, y: T + ih - hs - ht, width: Math.max(1, bw - 2), height: ht, fill: "#f59e0b" }));
  });
  const line = (key, stroke) => {
    const pts = t.map((b, i) => `${(L + i * bw + bw / 2).toFixed(1)},${y(b[key]).toFixed(1)}`).join(" ");
    svg.appendChild(svgEl("polyline", { points: pts, fill: "none", stroke, "stroke-width": 1.5 }));
  };
  line("passwords", "#f472b6");
  line("keys", "#a3e635");
  [0, Math.floor(t.length / 2), t.length - 1].forEach((i) => {
    const lab = svgEl("text", { x: L + i * bw + bw / 2, y: H - 6, "text-anchor": i === 0 ? "start" : i === t.length - 1 ? "end" : "middle", fill: "#8aa0bf", "font-size": 11 });
    lab.textContent = hhmm(t[i].time);
    svg.appendChild(lab);
  });
  box.appendChild(svg);
}

// ── metrics and tables ───────────────────────────────────────────────────────

function renderMetrics(s) {
  const box = document.getElementById("metrics");
  box.replaceChildren();
  const card = (label, value, sub) => {
    const c = el("div", null, "card");
    c.appendChild(el("div", label, "label"));
    c.appendChild(el("div", value, "value"));
    if (sub) c.appendChild(el("div", sub, "sub"));
    box.appendChild(c);
  };
  if (!s) { card("Statistics", "n/a", "stats endpoint not reachable"); return; }
  card("Connections", fmt(s.connections), `SSH ${fmt(s.sshConnections)} · Telnet ${fmt(s.telnetConnections)}`);
  card("Password attempts", fmt(s.passwordAttempts), `SSH ${fmt(s.sshPasswordAttempts)} · Telnet ${fmt(s.telnetPasswordAttempts)}`);
  card("Key attempts", fmt(s.sshKeyAttempts));
  card("Open now", fmt(s.openConnections), `SSH ${fmt(s.openSshConnections)} · Telnet ${fmt(s.openTelnetConnections)}`);
  card("Dropped (simulated)", fmt(s.droppedConnections));
  card("Reports sent", fmt(s.reportsSent), `${fmt(s.reportsTriggered)} IPs reported`);
  card("Uptime", s.uptime || "—");
}

function renderTable(id, columns, rows, emptyText) {
  const table = document.getElementById(id);
  table.replaceChildren();
  if (!rows.length) {
    const tr = el("tr"); const td = el("td", emptyText, "empty"); td.colSpan = columns.length; tr.appendChild(td); table.appendChild(tr);
    return;
  }
  const thead = el("thead"), hr = el("tr");
  for (const c of columns) hr.appendChild(el("th", c.title));
  thead.appendChild(hr); table.appendChild(thead);
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    for (const c of columns) tr.appendChild(el("td", c.value(r), c.cls));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
}

function renderTables(data) {
  renderTable("events", [
    { title: "Time", value: (r) => when(r.time) },
    { title: "Protocol", value: (r) => r.protocol },
    { title: "Source", value: (r) => r.src, cls: "mono" },
    { title: "Country", value: (r) => (r.countryCode ? r.countryCode + (r.country ? " – " + r.country : "") : "—") },
    { title: "Abuse score", value: (r) => (r.abuseConfidenceScore ?? "—") },
    { title: "Reports", value: (r) => (r.totalReports ?? "—") },
    { title: "Event", value: (r) => r.msg },
  ], data.connections || [], "No events yet");

  renderTable("attempts", [
    { title: "Time", value: (r) => when(r.time) },
    { title: "Protocol", value: (r) => r.protocol },
    { title: "Source", value: (r) => r.src, cls: "mono" },
    { title: "User", value: (r) => r.username, cls: "wrap mono" },
    { title: "Password / key", value: (r) => (r.type === "password" ? r.password : (r.keytype || "key") + " " + (r.fingerprint || "")), cls: "wrap mono" },
  ], data.attempts || [], "No credentials yet");
}

// ── refresh loop ─────────────────────────────────────────────────────────────

function warn(messages) {
  const box = document.getElementById("warnings");
  box.replaceChildren();
  for (const m of messages) box.appendChild(el("div", m, "warn"));
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const r = await fetch("/api/dashboard", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();

    const w = [];
    if (data.statsError) w.push("Statistics endpoint: " + data.statsError);
    if (data.logError) w.push("Log file: " + data.logError);
    warn(w);

    renderMetrics(data.stats);
    renderMap(data);
    renderTimeline(data);
    renderTables(data);
    status.textContent = "Last updated: " + new Date().toLocaleTimeString();
  } catch (e) {
    status.textContent = "Dashboard error: " + e.message;
  }
}

(async () => {
  await initMap(); // the map assets are cached by the browser; only the first load waits for them
  refresh();
  setInterval(refresh, REFRESH_MS);
})();
