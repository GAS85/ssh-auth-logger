"use strict";

// SSH Auth Logger dashboard server. Needs Node.js >= 18 (global fetch, AbortSignal.timeout).
const http = require("node:http");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

const PORT = Number(process.env.DASHBOARD_PORT || 8081);
// The dashboard shows captured credentials: listen on localhost unless told otherwise.
const BIND = process.env.DASHBOARD_BIND || "127.0.0.1";
const STATS_URL = process.env.STATS_URL || "http://127.0.0.1:8080/stats";
const STATS_TOKEN = process.env.STATS_TOKEN || ""; // same value as STATS_TOKEN of the honeypot
const LOG_FILE_PATH =
  process.env.LOG_FILE_PATH || "/var/log/ssh-auth-logger.log";
// Only the end of the log is read; the file grows without limit.
const LOG_TAIL_BYTES = Number(process.env.LOG_TAIL_BYTES || 512 * 1024);
const MY_LOCATION = (process.env.MY_LOCATION || "").toUpperCase();

// GeoJS country lookup: GET {GEOJS_BASE}/{ip}.json -> {"country":"US","name":"United States",...}
const GEOJS_BASE = (
  process.env.GEOJS_BASE || "https://get.geojs.io/v1/ip/country"
).replace(/\/+$/, "");
const GEO_TTL = 24 * 60 * 60 * 1000; // successful lookups
const GEO_FAIL_TTL = 5 * 60 * 1000; // failed lookups are remembered too, so GeoJS is not hit on every refresh
const GEO_MAX_CACHE = 5000;
const GEO_MAX_LOOKUPS = Number(process.env.GEO_MAX_LOOKUPS || 30); // new lookups per dashboard request
const GEO_CONCURRENCY = 5;

const WINDOW_MINUTES = 60;
const RESPONSE_TTL = 2000; // several browser tabs share one computation

const PUBLIC_DIR = path.resolve(__dirname, "public");

function send(res, status, data, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(type === "application/json" ? JSON.stringify(data) : data);
}

function timeOf(e) {
  const t = Date.parse(e && e.time ? e.time : "");
  return Number.isFinite(t) ? t : 0;
}

// Supports both newline-delimited JSON and pretty-printed JSON objects.
function parseLog(text) {
  const records = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let start = -1;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }

    if (c === '"') {
      inString = true;
      continue;
    }

    if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}" && depth > 0) {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          const obj = JSON.parse(text.slice(start, i + 1));
          if (obj && typeof obj === "object" && !Array.isArray(obj)) {
            records.push(obj);
          }
        } catch {}
        start = -1;
      }
    }
  }

  return records.sort((a, b) => timeOf(b) - timeOf(a));
}

// Reads at most the last maxBytes of the file, starting at a line boundary. truncated tells that older lines exist that were not read.
async function readLogTail(file, maxBytes) {
  const fh = await fs.promises.open(file, "r");
  try {
    const { size } = await fh.stat();
    const length = Math.min(size, maxBytes);
    const buf = Buffer.alloc(length);
    await fh.read(buf, 0, length, size - length);
    let text = buf.toString("utf8");
    const truncated = size > length;
    if (truncated) {
      const nl = text.indexOf("\n");
      text = nl === -1 ? "" : text.slice(nl + 1); // drop the cut-off first line
    }
    return { text, truncated };
  } finally {
    await fh.close();
  }
}

// Returns the address without IPv4-mapped prefix or zone id, or "" if it is not an IP address.
function normalizeIp(ip) {
  let s = String(ip || "").trim();
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s);
  if (mapped) s = mapped[1];
  return net.isIP(s) ? s : "";
}

function isPublicIPv4(ip) {
  const [a, b, c] = ip.split(".").map(Number);
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24 (not the whole 192.0.0.0/16: that holds public addresses)
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

function isPublicIPv6(ip) {
  const groups = ip.toLowerCase().split(":");
  const first = parseInt(groups[0] || "0", 16);
  if (first === 0) return false; // ::, ::1 and other ::/8 addresses
  if ((first & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
  if ((first & 0xffc0) === 0xfe80) return false; // fe80::/10 link local
  if ((first & 0xff00) === 0xff00) return false; // multicast
  if (first === 0x2001 && groups[1] === "db8") return false; // documentation
  return true;
}

function isPublicIp(ip) {
  const kind = net.isIP(ip);
  return kind === 4 ? isPublicIPv4(ip) : kind === 6 ? isPublicIPv6(ip) : false;
}

// ── Country lookup via GeoJS ─────────────────────────────────────────────────

const geoCache = new Map(); // ip -> { at, ttl, value }
const geoInflight = new Map(); // ip -> Promise
const NO_COUNTRY = Object.freeze({ countryCode: null, country: null });

function geoCached(ip) {
  const hit = geoCache.get(ip);
  if (hit && Date.now() - hit.at < hit.ttl) return hit.value;
  return undefined;
}

function geoStore(ip, value, ttl) {
  geoCache.delete(ip);
  geoCache.set(ip, { at: Date.now(), ttl, value });
  while (geoCache.size > GEO_MAX_CACHE) {
    geoCache.delete(geoCache.keys().next().value); // oldest first
  }
}

// Looks up one (normalised, public) IP. Never throws; failures give NO_COUNTRY and are cached briefly.
function geoLookup(ip) {
  const cached = geoCached(ip);
  if (cached) return Promise.resolve(cached);
  if (geoInflight.has(ip)) return geoInflight.get(ip);

  const p = (async () => {
    try {
      const response = await fetch(`${GEOJS_BASE}/${ip}.json`, {
        signal: AbortSignal.timeout(3000),
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`GeoJS HTTP ${response.status}`);

      const data = await response.json();
      // "country" is the two-letter code, "name" the country name.
      const code = String(data.country || "").toUpperCase();
      const value = /^[A-Z]{2}$/.test(code)
        ? { countryCode: code, country: data.name ? String(data.name) : null }
        : NO_COUNTRY;
      geoStore(ip, value, value === NO_COUNTRY ? GEO_FAIL_TTL : GEO_TTL);
      return value;
    } catch {
      geoStore(ip, NO_COUNTRY, GEO_FAIL_TTL);
      return NO_COUNTRY;
    } finally {
      geoInflight.delete(ip);
    }
  })();

  geoInflight.set(ip, p);
  return p;
}

// Resolves countries for the given IPs (in priority order). At most GEO_MAX_LOOKUPS addresses are looked up per call; the rest are filled in by later calls. Returns Map(original ip -> value) for every IP that has an answer, and the number still pending.
async function resolveCountries(ips) {
  const result = new Map();
  const todo = [];
  let pending = 0;

  for (const original of ips) {
    const ip = normalizeIp(original);
    if (!ip || !isPublicIp(ip)) {
      result.set(original, NO_COUNTRY); // private, reserved or not an address: no lookup
      continue;
    }
    const cached = geoCached(ip);
    if (cached) result.set(original, cached);
    else if (todo.length < GEO_MAX_LOOKUPS) todo.push([original, ip]);
    else pending++;
  }

  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const [original, ip] = todo[next++];
      result.set(original, await geoLookup(ip));
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(GEO_CONCURRENCY, todo.length) }, worker),
  );

  return { result, pending };
}

// ── Log events ───────────────────────────────────────────────────────────────

function classify(event) {
  const msg = String(event.msg || "").toLowerCase();
  const service = String(event.destinationServicename || "").toLowerCase();

  const protocol =
    service.includes("telnet") || event.protocol === "telnet"
      ? "telnet"
      : service.includes("ssh")
        ? "ssh"
        : "unknown";

  // "Connection dropped (simulated network issue)" contains "connection", so it has to be checked first.
  let type = "other";
  if (msg.includes("dropped")) type = "dropped";
  else if (msg.includes("connection")) type = "connection";
  else if (msg.includes("password") || msg.includes("login attempt"))
    type = "password";
  else if (msg.includes("request with key") || event.fingerprint) type = "key";

  return { protocol, type };
}

async function fetchStats() {
  const headers = STATS_TOKEN ? { Authorization: `Bearer ${STATS_TOKEN}` } : {};
  const r = await fetch(STATS_URL, {
    headers,
    signal: AbortSignal.timeout(3000),
  });
  if (!r.ok) throw new Error(`Stats HTTP ${r.status}`);
  return r.json();
}

async function buildDashboard() {
  const [statsResult, logText] = await Promise.allSettled([
    fetchStats(),
    readLogTail(LOG_FILE_PATH, LOG_TAIL_BYTES),
  ]);

  const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
  const raw = logText.status === "fulfilled" ? logText.value.text : "";
  const truncated = logText.status === "fulfilled" && logText.value.truncated;

  const events = parseLog(raw).map((e) => ({ ...e, ...classify(e) }));

  // The window is aligned to whole minutes. Buckets then keep their boundaries from one request to the next, so a bar only changes when events arrive; with a window relative to "now" every refresh would shift events between neighbouring buckets.
  const now = Date.now();
  const end = Math.floor(now / 60000) * 60000 + 60000; // end of the current minute
  const cutoff = end - WINDOW_MINUTES * 60000;

  // Latest events that belong to a source address (startup and abuse messages have none).
  const recent = events.filter((e) => e.src && e.type !== "other").slice(0, 10);
  const credentials = events
    .filter((e) => e.type === "password" || e.type === "key")
    .slice(0, 10);

  // Countries are counted over all connections of the window, not only the 10 shown.
  const windowConnections = events.filter((e) => {
    const t = timeOf(e);
    return e.type === "connection" && e.src && t >= cutoff && t < end;
  });

  // Recent events first, so what is on screen gets its country before the statistics do.
  const ips = [
    ...new Set(
      [...recent, ...windowConnections].map((e) => e.src).filter(Boolean),
    ),
  ];
  const { result: locations, pending } = await resolveCountries(ips);

  // GeoJS decides; the country in the log (AbuseIPDB) is only a fallback when GeoJS has no answer.
  const countryOf = (e) => {
    const geo = locations.get(e.src);
    return {
      countryCode: geo?.countryCode || e.countryCode || null,
      country: geo?.country || null,
    };
  };

  const connections = recent.map((e) => ({
    time: e.time,
    src: e.src || "Unknown",
    protocol: e.protocol,
    msg: e.msg || "",
    ...countryOf(e),
    abuseConfidenceScore: e.abuseConfidenceScore ?? null,
    totalReports: e.totalReports ?? null,
    type: e.type,
  }));

  const attempts = credentials.map((e) => ({
    time: e.time,
    src: e.src || "Unknown",
    protocol: e.protocol,
    type: e.type,
    username: e.duser || "(empty)",
    password: e.type === "password" ? e.password || "(empty)" : null,
    fingerprint: e.fingerprint || null,
    keytype: e.keytype || null,
  }));

  // Oldest event that was read. If the log was cut at the start, buckets before that point only have part of their events.
  const oldest = events.reduce((m, e) => {
    const t = timeOf(e);
    return t > 0 && t < m ? t : m;
  }, Infinity);

  // 60 one-minute buckets; bucket i covers [cutoff + i min, cutoff + (i+1) min). The last one is the current minute and still counting.
  const buckets = Array.from({ length: WINDOW_MINUTES }, (_, i) => {
    const startMs = cutoff + i * 60000;
    return {
      time: new Date(startMs).toISOString(),
    ssh: 0,
    telnet: 0,
    passwords: 0,
    keys: 0,
    dropped: 0,
      current: i === WINDOW_MINUTES - 1,
      complete: !(truncated && startMs < oldest),
    };
  });

  for (const e of events) {
    const t = timeOf(e);
    if (t < cutoff || t >= end) continue;
    const b = buckets[Math.floor((t - cutoff) / 60000)];

    if (e.type === "connection") {
      if (e.protocol === "ssh") b.ssh++;
      if (e.protocol === "telnet") b.telnet++;
    }
    if (e.type === "password") b.passwords++;
    if (e.type === "key") b.keys++;
    if (e.type === "dropped") b.dropped++;
  }

  const countryCounts = {};
  const countryNames = {};
  for (const e of windowConnections) {
    const { countryCode, country } = countryOf(e);
    if (!countryCode) continue;
    countryCounts[countryCode] = (countryCounts[countryCode] || 0) + 1;
    if (country) countryNames[countryCode] = country;
  }

  return {
    stats,
    statsError:
      statsResult.status === "rejected" ? statsResult.reason.message : null,
    logError: logText.status === "rejected" ? logText.reason.message : null,
    connections,
    attempts,
    timeline: buckets,
    countries: countryCounts,
    countryNames,
    geoPending: pending, // addresses whose country is still being looked up
    myLocation: MY_LOCATION || null,
    updatedAt: new Date().toISOString(),
  };
}

// One computation serves all requests within RESPONSE_TTL, also concurrent ones.
let dashboardCache = null; // { at, promise }
function getDashboard() {
  if (dashboardCache && Date.now() - dashboardCache.at < RESPONSE_TTL) {
    return dashboardCache.promise;
  }
  const entry = { at: Date.now(), promise: buildDashboard() };
  dashboardCache = entry;
  entry.promise.catch(() => {
    if (dashboardCache === entry) dashboardCache = null;
  });
  return entry.promise;
}

// ── Static files from public/ ────────────────────────────────────────────────

const STATIC_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
};

// The page only loads its own scripts, styles and data. Everything shown from the log is attacker controlled, so even a missed escaping bug must not be able to run script.
const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// Serves public/<pathname>; returns false if there is no such file.
async function serveStatic(req, res, pathname) {
  let rel;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    return false;
  }
  if (rel === "/") rel = "/index.html";
  if (rel.includes("\0") || rel.includes("\\")) return false;

  const file = path.resolve(PUBLIC_DIR, "." + path.posix.normalize(rel));
  const type = STATIC_TYPES[path.extname(file)];
  if (!type || !file.startsWith(PUBLIC_DIR + path.sep)) return false;

  let body;
  try {
    body = await fs.promises.readFile(file);
  } catch {
    return false;
  }
  const headers = {
    "Content-Type": `${type}; charset=utf-8`,
    "Content-Length": body.length,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    // Libraries and map data never change under the same file name; the page itself must always be fresh.
    "Cache-Control": rel.startsWith("/vendor/") ? "public, max-age=86400" : "no-cache",
  };
  if (type === "text/html") headers["Content-Security-Policy"] = PAGE_CSP;
  res.writeHead(200, headers);
  res.end(req.method === "HEAD" ? undefined : body);
  return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && url.pathname === "/api/dashboard") {
    try {
      send(res, 200, await getDashboard());
    } catch (error) {
      console.error("dashboard error:", error);
      send(res, 500, { error: "internal error" });
    }
    return;
  }

  if (url.pathname === "/favicon.ico") {
    res.writeHead(204, { "Cache-Control": "public, max-age=86400" });
    res.end();
    return;
  }

  if ((req.method === "GET" || req.method === "HEAD") && (await serveStatic(req, res, url.pathname))) {
    return;
  }

  send(res, 404, { error: "Not found" });
});

if (require.main === module) {
  server.listen(PORT, BIND, () => {
    console.log(`Dashboard listening on http://${BIND}:${PORT}`);
  });
}

module.exports = {
  server,
  parseLog,
  classify,
  normalizeIp,
  isPublicIp,
  buildDashboard,
};
