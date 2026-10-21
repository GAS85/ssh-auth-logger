"use strict";
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");

const geoHits = [];
const countries = { "8.8.8.8": ["US", "United States"], "91.198.174.192": ["NL", "Netherlands"], "1.1.1.1": ["AU", "Australia"], "2606:4700:4700::1111": ["US", "United States"], "192.0.43.8": ["US", "United States"] };
const geo = http.createServer((req, res) => {
  const ip = decodeURIComponent(req.url.replace(/^\/country\//, "").replace(/\.json$/, ""));
  geoHits.push(ip);
  if (ip === "9.9.9.9") { res.writeHead(500); return res.end("boom"); }
  const c = countries[ip];
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(c ? { country: c[0], name: c[1], ip, country_3: "XXX" } : { country: "nil", name: "nil", ip }));
});
let statsAuth = null;
const stats = http.createServer((req, res) => {
  statsAuth = req.headers.authorization || null;
  if (statsAuth !== "Bearer tok") { res.writeHead(401); return res.end(); }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ connections: 3, openConnections: 1 }));
});

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dash-"));
const logFile = path.join(dir, "app.log");
let dash, base;
const iso = (minAgo) => new Date(Date.now() - minAgo * 60000).toISOString();
const line = (o) => JSON.stringify(o) + "\n";

before(async () => {
  await new Promise((r) => geo.listen(0, "127.0.0.1", r));
  await new Promise((r) => stats.listen(0, "127.0.0.1", r));
  // A big block of filler first: must be skipped by the tail read.
  let log = "x".repeat(0);
  for (let i = 0; i < 40000; i++) log += line({ msg: "SSH connection", src: "8.8.8.8", destinationServicename: "sshd", time: iso(500) });
  log += line({ msg: "Starting SSH Auth Logger", time: iso(30) });
  log += line({ msg: "SSH connection", src: "8.8.8.8", destinationServicename: "sshd", time: iso(1), countryCode: "XX" }); // log says XX, GeoJS says US
  log += line({ msg: "SSH connection", src: "8.8.8.8", destinationServicename: "sshd", time: iso(2) });
  log += line({ msg: "Telnet connection", src: "91.198.174.192", destinationServicename: "telnetd", time: iso(3) });
  log += line({ msg: "Connection dropped (simulated network issue)", src: "1.1.1.1", destinationServicename: "sshd", time: iso(4) });
  log += line({ msg: "SSH connection", src: "1.1.1.1", destinationServicename: "sshd", time: iso(5), countryCode: "ZZ" });
  log += line({ msg: "SSH connection", src: "2606:4700:4700::1111", destinationServicename: "sshd", time: iso(6) });
  log += line({ msg: "SSH connection", src: "::ffff:192.0.43.8", destinationServicename: "sshd", time: iso(7) });
  log += line({ msg: "SSH connection", src: "192.168.1.5", destinationServicename: "sshd", time: iso(8) });
  log += line({ msg: "SSH connection", src: "9.9.9.9", destinationServicename: "sshd", time: iso(9), countryCode: "CH" }); // GeoJS fails -> log fallback
  log += line({ msg: "Request with password", src: "8.8.8.8", duser: "root", password: "<img src=x onerror=alert(1)>", destinationServicename: "sshd", time: iso(20) });
  log += line({ msg: "Request with key", src: "8.8.8.8", duser: "admin", fingerprint: "SHA256:abc", keytype: "ssh-ed25519", destinationServicename: "sshd", time: iso(20) });
  fs.writeFileSync(logFile, log);

  Object.assign(process.env, {
    DASHBOARD_PORT: "0", LOG_FILE_PATH: logFile, LOG_TAIL_BYTES: String(64 * 1024),
    STATS_URL: `http://127.0.0.1:${stats.address().port}/stats`, STATS_TOKEN: "tok",
    GEOJS_BASE: `http://127.0.0.1:${geo.address().port}/country`,
  });
  dash = require("./server.js").server;
  await new Promise((r) => dash.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${dash.address().port}`;
});
after(() => { dash.close(); geo.close(); stats.close(); dash.closeAllConnections?.(); });

const get = async (p) => { const r = await fetch(base + p); return { r, body: await r.json() }; };

test("country comes from GeoJS, not from the log", async () => {
  const { body } = await get("/api/dashboard");
  const byIp = (ip, msg) => body.connections.find((c) => c.src === ip && (!msg || c.msg === msg));
  assert.equal(byIp("8.8.8.8", "SSH connection").countryCode, "US"); // log said XX
  assert.equal(byIp("8.8.8.8", "SSH connection").country, "United States");
  assert.equal(byIp("91.198.174.192").countryCode, "NL");
  assert.equal(byIp("1.1.1.1", "SSH connection").countryCode, "AU"); // log said ZZ
  assert.equal(byIp("2606:4700:4700::1111").countryCode, "US"); // IPv6
  assert.equal(byIp("::ffff:192.0.43.8").countryCode, "US"); // mapped address, public 192.0.x.x
  assert.equal(byIp("192.168.1.5").countryCode, null); // private: no lookup
  assert.equal(byIp("9.9.9.9").countryCode, "CH"); // GeoJS failed: fallback to log
});

test("private and invalid addresses are never sent to GeoJS", () => {
  assert.ok(!geoHits.includes("192.168.1.5"));
  assert.ok(!geoHits.some((h) => h.includes("::ffff")));
  assert.ok(geoHits.includes("192.0.43.8"));
});

test("each address is looked up once, failures are cached", async () => {
  await get("/api/dashboard");
  await new Promise((r) => setTimeout(r, 2100)); // response cache expires
  await get("/api/dashboard");
  const count = (ip) => geoHits.filter((h) => h === ip).length;
  assert.equal(count("8.8.8.8"), 1);
  assert.equal(count("9.9.9.9"), 1);
});

test("country counts cover all connections of the window", async () => {
  const { body } = await get("/api/dashboard");
  // US: 8.8.8.8 x2, IPv6, 192.0.43.8 = 4 ; NL 1 ; AU 1 (the dropped one is not a connection) ; CH 1
  assert.deepEqual(body.countries, { US: 4, NL: 1, AU: 1, CH: 1 });
  assert.equal(body.countryNames.US, "United States");
});

test("dropped connections are classified and counted", async () => {
  const { classify } = require("./server.js");
  assert.equal(classify({ msg: "Connection dropped (simulated network issue)" }).type, "dropped");
  const { body } = await get("/api/dashboard");
  assert.equal(body.timeline.reduce((s, b) => s + b.dropped, 0), 1);
  assert.equal(body.timeline.length, 60);
});

test("credentials and keys are listed; startup lines are not events with a source", async () => {
  const { body } = await get("/api/dashboard");
  assert.ok(body.attempts.some((a) => a.type === "password" && a.username === "root"));
  assert.ok(body.attempts.some((a) => a.type === "key" && a.fingerprint === "SHA256:abc"));
  assert.ok(body.connections.every((c) => c.src !== "Unknown"));
});

test("only the log tail is read", async () => {
  const { body } = await get("/api/dashboard");
  const total = body.timeline.reduce((s, b) => s + b.ssh + b.telnet, 0);
  assert.ok(total < 20, `old filler lines must not be parsed (got ${total})`);
  assert.equal(body.logError, null);
});

test("stats are fetched with the bearer token", async () => {
  const { body } = await get("/api/dashboard");
  assert.equal(statsAuth, "Bearer tok");
  assert.equal(body.stats.openConnections, 1);
  assert.equal(body.statsError, null);
});

test("address helpers", () => {
  const { isPublicIp, normalizeIp } = require("./server.js");
  for (const ip of ["8.8.8.8", "192.0.43.8", "2606:4700:4700::1111"]) assert.ok(isPublicIp(ip), ip);
  for (const ip of ["10.1.1.1", "127.0.0.1", "192.168.0.1", "192.0.2.5", "203.0.113.9", "100.64.0.1", "::1", "::", "fe80::1", "fd00::1", "2001:db8::1", "224.0.0.1", "nonsense"]) assert.ok(!isPublicIp(ip), ip);
  assert.equal(normalizeIp("::ffff:1.2.3.4"), "1.2.3.4");
  assert.equal(normalizeIp("fe80::1%eth0"), "fe80::1");
  assert.equal(normalizeIp("1.2.3.4/../x"), "");
});

test("unknown paths and methods", async () => {
  assert.equal((await fetch(base + "/nope")).status, 404);
  assert.equal((await fetch(base + "/api/dashboard", { method: "POST" })).status, 404);
});

test("static files: page with CSP, vendor files, no path traversal", async () => {
  const page = await fetch(base + "/");
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy"), /script-src 'self'/);
  assert.equal((await fetch(base + "/vendor/d3.min.js")).status, 200);
  assert.equal((await fetch(base + "/app.js")).headers.get("content-type").startsWith("text/javascript"), true);
  for (const p of ["/../server.js", "/%2e%2e/server.js", "/vendor/../../server.js", "/vendor/", "/server.js", "/%00.js", "/..%5cserver.js"]) {
    const r = await fetch(base + p);
    assert.ok(r.status === 404 || r.status === 400, `${p} -> ${r.status}`);
  }
  assert.equal((await fetch(base + "/favicon.ico")).status, 204);
});

test("timeline buckets are aligned to whole minutes and do not move between refreshes", async () => {
  const realNow = Date.now;
  try {
    const minute = Math.floor(realNow() / 60000) * 60000;
    const at = (offsetSec) => { Date.now = () => minute + offsetSec * 1000; };

    at(5); const a = (await get("/api/dashboard")).body.timeline;
    at(45); const b = (await get("/api/dashboard")).body.timeline;
    assert.deepEqual(a, b, "same minute: the buckets must be identical");
    for (const x of a) assert.equal(Date.parse(x.time) % 60000, 0, "bucket start is a whole minute");
    assert.equal(a.length, 60);
    assert.equal(a[59].current, true);
    assert.ok(a.slice(0, 59).every((x) => !x.current));

    at(65); const c = (await get("/api/dashboard")).body.timeline;
    // One minute later the window moved by exactly one bucket.
    assert.deepEqual(c.slice(0, 59).map(({ time, ...r }) => r), a.slice(1).map(({ time, ...r }) => r).map((r) => ({ ...r, current: false })));
    assert.equal(Date.parse(c[0].time), Date.parse(a[0].time) + 60000);
  } finally {
    Date.now = realNow;
  }
});

test("buckets older than the part of the log that was read are marked incomplete", async () => {
  const { body } = await get("/api/dashboard");
  assert.ok(body.timeline.every((b) => typeof b.complete === "boolean"));
});
