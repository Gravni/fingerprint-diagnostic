// Network-layer fingerprint capture server.
//
// The browser reveals its TLS ClientHello — JA4, cipher/extension order, the
// ALPN list — before any HTTP or JavaScript, and only the server terminating
// TLS can read it. Cloudflare terminates TLS for the panel, so this server must
// be hit DIRECTLY, on its own domain pointed straight at the machine.
//
// Flow: peek the first TCP chunk (the ClientHello), compute JA4, then terminate
// TLS and read the HTTP request for the one-time token the panel issued. Post
// the result back to the panel, which resolves the token to the employee. The
// browser sees a "готово" page.
//
// Run (needs a real cert so the browser completes the request that carries the
// token — a self-signed cert is generated only as a fallback for local testing):
//   CERT_FILE=/etc/letsencrypt/live/DOMAIN/fullchain.pem \
//   KEY_FILE=/etc/letsencrypt/live/DOMAIN/privkey.pem \
//   CAPTURE_SECRET=<same as panel> PANEL_URL=http://127.0.0.1:3400 PORT=8443 \
//   node --experimental-strip-types scripts/capture-server.mjs

import net from "node:net";
import https from "node:https";
import tls from "node:tls";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execSync } from "node:child_process";
import { fingerprintFromClientHello, clientHelloComplete } from "../lib/ja4.ts";

const CAPTURE_BUILD = process.env.CAPTURE_BUILD || "net-v5";
const PORT = Number(process.env.PORT || 8443);
const PANEL_URL = (process.env.PANEL_URL || "http://127.0.0.1:3400").replace(/\/+$/, "");
const SECRET = process.env.CAPTURE_SECRET || "";
if (!SECRET) { console.error("CAPTURE_SECRET не задан — панель не примет результат"); process.exit(1); }

// Cert: real one from env, or a throwaway self-signed for local testing.
let creds;
if (process.env.CERT_FILE && process.env.KEY_FILE) {
  creds = { cert: readFileSync(process.env.CERT_FILE), key: readFileSync(process.env.KEY_FILE) };
  console.log("сертификат: из файлов");
} else {
  console.log("сертификат: самоподписанный (только для локального теста)");
  const dir = mkdtempSync(join(tmpdir(), "cap-"));
  const kf = join(dir, "k.pem"), cf = join(dir, "c.pem");
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes -keyout ${kf} -out ${cf} ` +
    `-days 1 -subj /CN=capture.local 2>/dev/null`,
  );
  creds = { key: readFileSync(kf), cert: readFileSync(cf) };
}

// SNI: serve several domains from one process so the cross-site OOPIF host
// (a SECOND registrable domain — a true cross-site, not a same-site subdomain)
// and the JA4 host share this endpoint. TLS_DOMAINS is a comma list; each has a
// Let's Encrypt cert at /etc/letsencrypt/live/<domain>/. A servername with no
// context falls back to the default cert above.
const sniContexts = new Map();
for (const d of (process.env.TLS_DOMAINS || "").split(",").map((s) => s.trim()).filter(Boolean)) {
  try {
    sniContexts.set(d, tls.createSecureContext({
      cert: readFileSync(`/etc/letsencrypt/live/${d}/fullchain.pem`),
      key: readFileSync(`/etc/letsencrypt/live/${d}/privkey.pem`),
    }));
    console.log("SNI cert загружен:", d);
  } catch (e) {
    console.warn("SNI cert не загрузился для", d, "-", e.message);
  }
}
function sniCallback(servername, cb) {
  cb(null, sniContexts.get(servername) || undefined); // undefined => default creds
}

const DONE_PAGE = Buffer.from(
  "<!doctype html><meta charset=utf-8><title>готово</title>" +
  "<body style='font:14px system-ui;background:#0d1117;color:#c9d1d9;padding:40px'>" +
  "<h3>Сетевой отпечаток снят ✓</h3><p>Можно закрывать вкладку.</p>",
  "utf8",
);

// Returns TRUE only after the panel CONFIRMS it persisted the record — the
// capture is not "done" until the panel saved it (Codex v4.3 #8: fired ≠ ack).
async function postResult(token, m) {
  try {
    const r = await fetch(`${PANEL_URL}/api/fingerprint/net-result`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-capture-secret": SECRET },
      body: JSON.stringify({ token, m }),
    });
    if (!r.ok) { console.warn("панель отклонила результат:", r.status, await r.text()); return false; }
    return true;
  } catch (e) {
    console.warn("не смог отдать результат панели:", e.message);
    return false;
  }
}

// Cross-origin OOPIF probe page. Served on THIS host (fp.*), a genuinely
// different origin from the panel, so the collector runs in a real cross-site
// iframe. The collector source is fetched from the panel (over the tunnel) and
// cached; the page runs collect() and postMessages the result to its parent.
// Cache the collector keyed by the panel's browserCollectorBuild hash — when the
// collector changes, the build id changes and we re-fetch automatically, instead
// of serving a stale copy until a manual restart (Codex v4.3 #9).
let collectorCache = null, collectorBuild = null;
async function panelBuild() {
  try { const r = await fetch(`${PANEL_URL}/api/fingerprint/build`); if (r.ok) return (await r.json()).browserCollectorBuild || null; } catch { /* */ }
  return null;
}
async function getCollector() {
  const build = await panelBuild();
  if (collectorCache && build && build === collectorBuild) return collectorCache; // fresh
  try {
    const r = await fetch(`${PANEL_URL}/fingerprint/collector`);
    if (r.ok) { collectorCache = await r.text(); collectorBuild = build; return collectorCache; }
  } catch { /* panel unreachable */ }
  return collectorCache; // fall back to last-known if the panel blips
}
function xprobePage(collector) {
  const safe = String(collector).replace(/<\/script>/gi, "<\\/script>");
  return "<!doctype html><meta charset=utf-8><body><script>" + safe + "</script><script>" +
    // ok() must never throw: a non-cloneable value in the snapshot would make the
    // raw postMessage throw and the parent would hang to its timeout. Try raw,
    // fall back to a JSON-safe copy, then an error stub — always post SOMETHING.
    "(function(){function ok(m){try{parent.postMessage({__fpx:1,m:m},'*');}catch(_e){try{parent.postMessage({__fpx:1,m:JSON.parse(JSON.stringify(m))},'*');}catch(_e2){parent.postMessage({__fpx:1,m:{_context:'cross-origin-iframe',error:'post-failed:'+String(_e&&_e.name)}},'*');}}}" +
    // Isolation metadata recorded at collection: child origin/host (this
    // second-registrable-domain page) vs the parent (the panel, via referrer).
    // crossSite is asserted from differing registrable domains; the definitive
    // process-isolation proof is captured separately by the Playwright smoke.
    "function iso(){try{var ph=(document.referrer||'').split('/')[2]||'';return {context:'cross-origin-iframe',childOrigin:location.origin,childHost:location.host,parentReferrerHost:ph,crossOrigin:location.host!==ph,note:'child is a distinct registrable domain from the panel'};}catch(_){return {context:'cross-origin-iframe',error:'iso-failed'};}}" +
    "Promise.resolve().then(function(){return self.LinkageProbe.collect('cross-origin-iframe');})" +
    ".then(function(m){try{m._isolation=iso();}catch(_){}ok(m);},function(e){ok({_context:'cross-origin-iframe',error:String(e),_isolation:iso()});});})();</script>";
}

// JA4 read from the raw ClientHello, keyed by the client's ephemeral port so
// the HTTPS request handler — which sees the same peer — can pair them up.
const pending = new Map();

const httpsServer = https.createServer(
  { key: creds.key, cert: creds.cert, ALPNProtocols: ["http/1.1"], SNICallback: sniCallback },
  async (req, res) => {
    const k = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
    // Cross-origin probe page: serve HTML, don't consume the JA4 pairing.
    if ((req.url || "").split("?")[0] === "/xprobe") {
      pending.delete(k);
      const col = await getCollector();
      if (!col) { res.writeHead(503, { "content-type": "text/plain" }); res.end("collector unavailable"); return; }
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
        // only the panel may frame this (valid CSP, unlike the old invalid XFO);
        // localhost is included so the #14 Playwright smoke (which drives the
        // panel directly on 127.0.0.1) can exercise the cross-origin OOPIF too.
        // close the connection so the next JA4 request gets a fresh ClientHello.
        "content-security-policy": "frame-ancestors https://panel.example http://127.0.0.1:3401 http://localhost:3401",
        "connection": "close",
      });
      res.end(xprobePage(col));
      return;
    }
    const entry = pending.get(k); pending.delete(k);
    const fp = entry?.fp || null;
    const token = (() => {
      try { return new URL(req.url, "https://x").searchParams.get("token"); }
      catch { return null; }
    })();

    if (!fp) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("не удалось прочитать TLS-рукопожатие");
      return;
    }
    const ch = fp.raw;
    // HTTP-layer signals (Codex v4 §Network / v4.2 #11): header NAMES *and values*
    // in wire order, Client Hints, Fetch Metadata, HTTP version — a structured
    // status where a field is absent, never a vanished field. req.rawHeaders is
    // [name,value,name,value,…].
    const rawNames = [], rawPairs = [];
    const rawHeadersTyped = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      rawNames.push(req.rawHeaders[i]);
      rawPairs.push(req.rawHeaders[i] + ": " + req.rawHeaders[i + 1]);
      rawHeadersTyped.push({ name: req.rawHeaders[i], value: req.rawHeaders[i + 1] }); // typed, wire order
    }
    const h = (name) => (req.headers[name] != null ? req.headers[name] : "absent");
    const hex4 = (n) => ("000" + n.toString(16)).slice(-4);
    const isGrease = (n) => (n & 0x0f0f) === 0x0a0a;
    const ra = req.socket.remoteAddress || "";
    const round = (() => { try { return Number(new URL(req.url, "https://x").searchParams.get("round")) || 1; } catch { return 1; } })();
    const m = {
      // Versioned, TYPED network schema (Codex v4.3 #8). Flat string fields below
      // are kept for the human report + net-v4 back-compat; the typed structures
      // are the canonical machine form.
      netSchemaVersion: "net-v5",
      round,                                   // Accept-CH round index (1 = prime, 2 = with hints)
      tlsTyped: {
        ciphers: (ch.ciphers || []), extensions: (ch.extensions || []),
        curves: (ch.curves || []), pointFormats: (ch.pointFormats || []),
        sigAlgs: (ch.sigAlgs || []), alpnOffered: (ch.alpn || []),
      },
      httpHeadersTyped: rawHeadersTyped,       // [{name,value}] in wire order
      // observed transport peer (Codex v4.2 #11)
      observedIp: ra || "unknown",
      observedIpFamily: ra.indexOf(":") >= 0 ? "ipv6" : /\d+\.\d+\.\d+\.\d+/.test(ra) ? "ipv4" : "unknown",
      // TLS / transport — raw ClientHello fields IN WIRE ORDER (GREASE kept)
      ja4: fp.ja4,
      ja3: fp.ja3,                        // MD5 of the canonical 5-field JA3 string
      ja3String: fp.ja3String,            // raw JA3 string (now incl. curves + point formats)
      curvesHex: (ch.curves || []).map(hex4).join(","),
      pointFormatsHex: (ch.pointFormats || []).map(function (x) { return ("0" + x.toString(16)).slice(-2); }).join(","),
      tlsVersion: fp.tlsVersion,
      sni: fp.sni ?? "none",
      alpnOffered: (ch.alpn || []).join(","),          // browser's ALPN list
      alpnNegotiated: req.socket.alpnProtocol || "none",
      cipherListHex: (ch.ciphers || []).map(hex4).join(","),        // wire order, GREASE incl.
      cipherCount: String((ch.ciphers || []).filter((c) => !isGrease(c)).length),
      extensionListHex: (ch.extensions || []).map(hex4).join(","),  // wire order, GREASE incl.
      extensionCount: String((ch.extensions || []).length),
      sigAlgsHex: (ch.sigAlgs || []).map(hex4).join(","),           // wire order
      // HTTP
      httpVersion: req.httpVersion || "unknown",
      headerOrder: rawNames.join(","),
      headerNameValueOrder: rawPairs.join(" | "),      // names + VALUES in wire order (#11)
      headerCount: String(rawNames.length),
      userAgent: h("user-agent"),
      acceptLanguage: h("accept-language"),
      accept: h("accept"),
      acceptEncoding: h("accept-encoding"),
      // full high-entropy Client-Hints set (what the browser actually delegated)
      secChUa: h("sec-ch-ua"),
      secChUaMobile: h("sec-ch-ua-mobile"),
      secChUaPlatform: h("sec-ch-ua-platform"),
      secChUaPlatformVersion: h("sec-ch-ua-platform-version"),
      secChUaArch: h("sec-ch-ua-arch"),
      secChUaBitness: h("sec-ch-ua-bitness"),
      secChUaModel: h("sec-ch-ua-model"),
      secChUaFullVersionList: h("sec-ch-ua-full-version-list"),
      secChUaWow64: h("sec-ch-ua-wow64"),
      // Accept-CH round-trip: we advertise Accept-CH + Critical-CH in the response
      // (below); this field records which high-entropy hints actually arrived.
      acceptChAdvertised: "platform-version,arch,bitness,model,full-version-list,wow64",
      secFetchSite: h("sec-fetch-site"),
      secFetchMode: h("sec-fetch-mode"),
      secFetchDest: h("sec-fetch-dest"),
      secFetchUser: h("sec-fetch-user"),
      priority: h("priority"),
      // Layers this endpoint does NOT terminate — a STRUCTURED status, never a
      // vanished field (Codex v4.2 #11). h2 pseudo-header order + SETTINGS need
      // raw HTTP/2 frame parsing (a follow-up like the JA4 ClientHello peek);
      // this endpoint negotiates http/1.1. WebRTC/STUN is captured in the browser
      // webrtc block; DNS/H3/QUIC/WebTransport/WS are out of this endpoint's scope.
      http2: req.socket.alpnProtocol === "h2" ? "negotiated" : "not-negotiated (endpoint offers http/1.1)",
      http2Settings: "not-captured (needs raw h2 frame parse)",
      http2PseudoHeaderOrder: "not-captured (needs raw h2 frame parse)",
      http3Quic: "not-captured (endpoint is TCP/TLS)",
      webTransport: "not-captured (no WebTransport endpoint)",
      webSocket: "not-captured (no WS endpoint)",
      webrtcStun: "captured in browser webrtc block (host-only, no external STUN)",
      dns: "not-observable at this endpoint",
      // provenance — this layer terminated TLS directly (our capture endpoint),
      // so the JA4/TLS metadata is genuine, not a CDN/proxy re-handshake.
      tlsTerminatedBy: "capture-endpoint",
      parserVersion: "net-v5",
      captureBuild: CAPTURE_BUILD,
    };
    // AWAIT the panel save before responding: the browser's fetch resolves only
    // after the record is persisted, so the run-manifest / side-status check that
    // follows sees a real network record (Codex v4.3 #8).
    const saved = token ? await postResult(token, m) : false;
    res.writeHead(token ? (saved ? 200 : 502) : 400, {
      "content-type": (token && saved) ? "text/html; charset=utf-8" : "text/plain; charset=utf-8",
      "cache-control": "no-store",
      // Advertise high-entropy Client-Hints so a follow-up carries them — the
      // Accept-CH / Critical-CH round-trip (Codex v4.2 #11).
      "accept-ch": "sec-ch-ua-platform-version, sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-model, sec-ch-ua-full-version-list, sec-ch-ua-wow64",
      "critical-ch": "sec-ch-ua-platform-version, sec-ch-ua-full-version-list",
      // fresh TLS connection per capture → a new ClientHello each time (JA4).
      "connection": "close",
    });
    res.end((token && saved) ? DONE_PAGE : Buffer.from(token ? "панель не сохранила сетевую запись" : "нет токена — открой через панель", "utf8"));
  },
);
httpsServer.on("clientError", (_e, sock) => { try { sock.destroy(); } catch {} });

// Raw TCP front: peek the ClientHello, then hand the socket to the HTTPS server
// to terminate TLS and parse HTTP normally.
const MAX_HELLO = 65536; // a ClientHello may span several TLS records — cap generously

const server = net.createServer((socket) => {
  socket.setTimeout(15_000, () => socket.destroy());

  // Accumulate until the full ClientHello handshake has arrived — across as MANY
  // TLS records as it takes (Codex v4.3 #8). A modern Chrome hello (post-quantum
  // key shares) is ~1.5-2 KB and routinely splits across TCP segments AND multiple
  // TLS records; clientHelloComplete() reassembles the handshake fragments and
  // tells us when the whole message is in.
  const chunks = [];
  let total = 0, isTls = -1;
  const onData = (chunk) => {
    chunks.push(chunk);
    total += chunk.length;
    const buf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, total);

    if (isTls < 0 && buf.length >= 1) isTls = buf[0] === 0x16 ? 1 : 0; // 0 = not TLS
    if (isTls === 1 && !clientHelloComplete(buf) && total < MAX_HELLO) return; // wait for more records
    if (isTls < 0) return;                                                     // need ≥1 byte

    socket.removeListener("data", onData);
    const fp = isTls === 1 ? fingerprintFromClientHello(buf) : null;
    if (fp) pending.set(`${socket.remoteAddress}:${socket.remotePort}`, { fp, at: Date.now() });

    // Restore the bytes and hand the socket to the TLS/HTTP server.
    socket.pause();
    socket.unshift(buf);
    httpsServer.emit("connection", socket);
    process.nextTick(() => socket.resume());
  };
  socket.on("data", onData);
  socket.on("error", () => socket.destroy());
});

// A peeked connection whose HTTP request never arrives (browser aborted on a
// cert warning) would leak its pending entry. Sweep stale ones.
setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [k, v] of pending) if (v.at < cutoff) pending.delete(k);
}, 60_000).unref();

server.on("error", (e) => { console.error("сервер:", e.message); process.exit(1); });
server.listen(PORT, () => console.log(`приёмник JA4 слушает :${PORT} → панель ${PANEL_URL}`));
