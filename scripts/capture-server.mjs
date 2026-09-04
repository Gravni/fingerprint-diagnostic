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
// token — a self-signed cert is generated only with the explicit
// ALLOW_SELF_SIGNED_FOR_TESTS=1 test flag):
//   CERT_FILE=/etc/letsencrypt/live/DOMAIN/fullchain.pem \
//   KEY_FILE=/etc/letsencrypt/live/DOMAIN/privkey.pem \
//   CAPTURE_SECRET=<same as panel> PANEL_URL=http://127.0.0.1:3400 PORT=8443 \
//   node --experimental-strip-types scripts/capture-server.mjs

import net from "node:net";
import http from "node:http";
import http2 from "node:http2";
import tls from "node:tls";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { fingerprintFromClientHello, clientHelloComplete } from "../lib/ja4.ts";
import { H2PrefaceObserver, analyzeH2RawHeaders } from "../lib/h2-observe.mjs";
import { computeBuildIdentity } from "../lib/fp-provenance.mjs";
import { FP_EXECUTABLE_TREE } from "../lib/fp-executable-tree.mjs";
import { renderBoundChildProbe } from "../lib/fp-probe-artifact.mjs";

const REPOSITORY_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CAPTURE_IDENTITY = computeBuildIdentity({
  rootDir: REPOSITORY_ROOT,
  schemaVersion: "net-v6",
  executableTree: FP_EXECUTABLE_TREE,
});
const CAPTURE_BUILD = CAPTURE_IDENTITY.buildId;
if (process.env.CAPTURE_BUILD && process.env.CAPTURE_BUILD !== CAPTURE_BUILD) {
  throw new Error(`CAPTURE_BUILD mismatch: configured ${process.env.CAPTURE_BUILD}, actual ${CAPTURE_BUILD}`);
}
const PORT = Number(process.env.PORT || 8443);
function parsePanelUrl(raw) {
  let url;
  try { url = new URL(raw); }
  catch { throw new Error("PANEL_URL must be an exact URL origin"); }
  const exact = raw === url.origin || raw === `${url.origin}/`;
  const loopbackHttp = url.protocol === "http:"
    && (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (!exact || url.username || url.password || url.search || url.hash
      || (url.protocol !== "https:" && !loopbackHttp)) {
    throw new Error("PANEL_URL must be an exact HTTPS origin (HTTP is allowed only on loopback)");
  }
  return url.origin;
}
let PANEL_URL;
try { PANEL_URL = parsePanelUrl(process.env.PANEL_URL || "http://127.0.0.1:3400"); }
catch (error) { console.error(error.message); process.exit(1); }
const SECRET = process.env.CAPTURE_SECRET || "";
if (!SECRET) { console.error("CAPTURE_SECRET не задан — панель не примет результат"); process.exit(1); }

// `/xprobe` executes privileged collector source in a cross-site frame. Its
// framing policy must never be a sample hostname or an implicit wildcard.
// Accept only exact HTTP(S) origins and build CSP exclusively from this list.
function parsePublicOrigins(raw) {
  if (!raw || !raw.trim()) throw new Error("PANEL_PUBLIC_ORIGINS is required");
  const origins = [];
  for (const item of raw.split(",").map((x) => x.trim()).filter(Boolean)) {
    let url;
    try { url = new URL(item); }
    catch { throw new Error(`PANEL_PUBLIC_ORIGINS contains an invalid URL: ${item}`); }
    const exactOrigin = item === url.origin || item === `${url.origin}/`;
    const loopbackHttp = url.protocol === "http:"
      && (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
    if (!exactOrigin || (url.protocol !== "https:" && !loopbackHttp)
        || url.username || url.password || url.search || url.hash) {
      throw new Error(`PANEL_PUBLIC_ORIGINS must contain exact HTTPS origins (HTTP only on loopback): ${item}`);
    }
    if (!origins.includes(url.origin)) origins.push(url.origin);
  }
  if (!origins.length) throw new Error("PANEL_PUBLIC_ORIGINS is required");
  return Object.freeze(origins);
}

let PANEL_PUBLIC_ORIGINS;
try { PANEL_PUBLIC_ORIGINS = parsePublicOrigins(process.env.PANEL_PUBLIC_ORIGINS); }
catch (error) { console.error(error.message); process.exit(1); }
const FRAME_ANCESTORS_CSP = `default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors ${PANEL_PUBLIC_ORIGINS.join(" ")}`;

const PANEL_FETCH_TIMEOUT_MS = Number(process.env.PANEL_FETCH_TIMEOUT_MS || 5_000);
if (!Number.isInteger(PANEL_FETCH_TIMEOUT_MS) || PANEL_FETCH_TIMEOUT_MS < 50 || PANEL_FETCH_TIMEOUT_MS > 30_000) {
  console.error("PANEL_FETCH_TIMEOUT_MS must be an integer between 50 and 30000");
  process.exit(1);
}

// The timeout bounds *time*, but without byte ceilings a compromised or
// misconfigured panel can still make the capture process buffer an arbitrary
// response. Keep separate, route-sized ceilings: the build descriptor and
// persistence acknowledgement are tiny; only the executable collector may be
// a few MiB.
const PANEL_BUILD_MAX_BYTES = 64 * 1024;
const PANEL_COLLECTOR_MAX_BYTES = 8 * 1024 * 1024;
const PANEL_ACK_MAX_BYTES = 64 * 1024;

async function readPanelBody(response, maxBytes) {
  const declared = response.headers.get("content-length");
  if (declared != null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    try { await response.body?.cancel("panel-response-too-large"); } catch {}
    throw new Error("panel-response-too-large");
  }
  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0, complete = false;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) { complete = true; break; }
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maxBytes) throw new Error("panel-response-too-large");
      chunks.push(chunk);
    }
  } finally {
    if (!complete) {
      try { await reader.cancel("panel-response-too-large"); } catch {}
    }
    try { reader.releaseLock(); } catch {}
  }
  return Buffer.concat(chunks, total);
}

async function readPanelText(response, maxBytes) {
  return (await readPanelBody(response, maxBytes)).toString("utf8");
}

// Every call to the private panel is bounded and is also cancelled when the
// downstream browser request disappears. Redirects are rejected so a panel
// configuration mistake cannot turn this service into an unexpected egress.
async function withPanelResponse(path, init, callerSignal, consume) {
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort(callerSignal?.reason || new Error("downstream-aborted"));
  if (callerSignal?.aborted) abortFromCaller();
  else callerSignal?.addEventListener("abort", abortFromCaller, { once: true });
  const timeout = setTimeout(() => controller.abort(new Error("panel-fetch-timeout")), PANEL_FETCH_TIMEOUT_MS);
  timeout.unref?.();
  try {
    const response = await fetch(`${PANEL_URL}${path}`, {
      ...init,
      redirect: "error",
      cache: "no-store",
      signal: controller.signal,
    });
    // Keep the timer and downstream cancellation active while consuming the
    // body too. `fetch()` itself resolves at headers and a stalled JSON/text
    // body would otherwise escape the deadline.
    return await consume(response);
  } finally {
    clearTimeout(timeout);
    callerSignal?.removeEventListener("abort", abortFromCaller);
  }
}

// Certificate configuration is fail-closed. A self-signed certificate is
// available only behind an explicit test-only opt-in; a half-configured pair
// must never silently downgrade a production listener.
let creds;
const CERT_FILE = process.env.CERT_FILE || "";
const KEY_FILE = process.env.KEY_FILE || "";
const ALLOW_SELF_SIGNED_FOR_TESTS = process.env.ALLOW_SELF_SIGNED_FOR_TESTS === "1";
if (!!CERT_FILE !== !!KEY_FILE) {
  console.error("CERT_FILE and KEY_FILE must be configured as one certificate pair");
  process.exit(1);
} else if (CERT_FILE && KEY_FILE) {
  try {
    creds = { cert: readFileSync(CERT_FILE), key: readFileSync(KEY_FILE) };
  } catch (error) {
    console.error("failed to load CERT_FILE/KEY_FILE certificate pair:", error.message);
    process.exit(1);
  }
  console.log("сертификат: из файлов");
} else if (ALLOW_SELF_SIGNED_FOR_TESTS) {
  console.log("сертификат: самоподписанный (explicit test mode)");
  const dir = mkdtempSync(join(tmpdir(), "cap-"));
  const kf = join(dir, "k.pem"), cf = join(dir, "c.pem");
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", kf, "-out", cf, "-days", "1", "-subj", "/CN=capture.local"],
    { stdio: "ignore" });
    creds = { key: readFileSync(kf), cert: readFileSync(cf) };
  } finally {
    // The key is already held in memory by the TLS context; never leave the
    // test-only private key in a temp directory after startup.
    rmSync(dir, { recursive: true, force: true });
  }
} else {
  console.error("production certificate required: set CERT_FILE and KEY_FILE (self-signed is test-only)");
  process.exit(1);
}

// SNI: serve several domains from one process so the cross-site OOPIF host
// (a SECOND registrable domain — a true cross-site, not a same-site subdomain)
// and the JA4 host share this endpoint. TLS_DOMAINS is a comma list; each has a
// Let's Encrypt cert at /etc/letsencrypt/live/<domain>/. A servername with no
// context falls back to the default cert above.
const sniContexts = new Map();
for (const d of (process.env.TLS_DOMAINS || "").split(",").map((s) => s.trim()).filter(Boolean)) {
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(d)) {
    console.error("invalid TLS_DOMAINS hostname:", d);
    process.exit(1);
  }
  try {
    sniContexts.set(d, tls.createSecureContext({
      cert: readFileSync(`/etc/letsencrypt/live/${d}/fullchain.pem`),
      key: readFileSync(`/etc/letsencrypt/live/${d}/privkey.pem`),
    }));
    console.log("SNI cert загружен:", d);
  } catch (e) {
    console.error("SNI certificate failed to load for", d, "-", e.message);
    process.exit(1);
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
async function postResult(token, m, callerSignal = null) {
  const deadlineAt = Date.now() + PANEL_FETCH_TIMEOUT_MS;
  const idempotencyKey = createHash("sha256")
    .update(`network\0${token}\0${m.captureBuild}\0${m.round}`)
    .digest("hex");
  try {
    return await withPanelResponse("/api/fingerprint/net-result", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-capture-secret": SECRET,
        "x-capture-deadline": String(deadlineAt),
        "x-idempotency-key": idempotencyKey,
      },
      body: JSON.stringify({ token, m, delivery: { deadlineAt, idempotencyKey } }),
    }, callerSignal, async (r) => {
      if (!r.ok) {
        console.warn("панель отклонила результат:", r.status, await readPanelText(r, PANEL_ACK_MAX_BYTES));
        return false;
      }
      // Drain a response body if a proxy added one; acknowledgement is complete
      // only while the bounded request is still alive.
      await readPanelBody(r, PANEL_ACK_MAX_BYTES);
      return true;
    });
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
let collectorCache = null, collectorBuild = null, collectorArtifactSha256 = null;
const artifactByBuild = new Map();
const SHA256_RE = /^[0-9a-f]{64}$/;
async function panelCollectorDescriptor(callerSignal = null) {
  try {
    return await withPanelResponse("/api/fingerprint/collector-descriptor", {
      headers: { "x-capture-secret": SECRET },
    }, callerSignal, async (r) => {
      if (!r.ok) return null;
      const descriptor = JSON.parse(await readPanelText(r, PANEL_BUILD_MAX_BYTES));
      const build = descriptor?.browserCollectorBuild;
      // A product/tree build id alone does not authenticate this exact response
      // body. Require the build endpoint to bind the collector artifact hash too.
      const artifactSha256 = descriptor?.browserCollectorArtifactSha256;
      if (!SHA256_RE.test(build || "") || !SHA256_RE.test(artifactSha256 || "")) return null;
      return { build, artifactSha256 };
    });
  } catch { /* fail closed below */ }
  return null;
}
async function getCollector(callerSignal = null) {
  const descriptor = await panelCollectorDescriptor(callerSignal);
  // Never serve the last-known source when the authoritative build endpoint is
  // unreachable, malformed, or labelled with a human version string.
  if (!descriptor) return null;
  const priorArtifact = artifactByBuild.get(descriptor.build);
  if (priorArtifact && priorArtifact !== descriptor.artifactSha256) return null;
  if (collectorCache && descriptor.build === collectorBuild
      && descriptor.artifactSha256 === collectorArtifactSha256) {
    return Object.freeze({
      source: collectorCache,
      build: collectorBuild,
      artifactSha256: collectorArtifactSha256,
    });
  }
  try {
    return await withPanelResponse("/fingerprint/collector", {
      headers: { "x-capture-secret": SECRET },
    }, callerSignal, async (r) => {
      if (!r.ok) return null;
      const source = await readPanelText(r, PANEL_COLLECTOR_MAX_BYTES);
      const actualSha256 = createHash("sha256").update(source).digest("hex");
      if (actualSha256 !== descriptor.artifactSha256) return null;
      // Re-check after the awaited body read. Two concurrent first requests
      // may have observed an unbound build before either source arrived; this
      // atomic check+set section ensures the second one cannot rebind it.
      const nowBound = artifactByBuild.get(descriptor.build);
      if (nowBound && nowBound !== descriptor.artifactSha256) return null;
      artifactByBuild.set(descriptor.build, descriptor.artifactSha256);
      collectorCache = source;
      collectorBuild = descriptor.build;
      collectorArtifactSha256 = descriptor.artifactSha256;
      return Object.freeze({
        source: collectorCache,
        build: collectorBuild,
        artifactSha256: collectorArtifactSha256,
      });
    });
  } catch { /* panel unreachable */ }
  return null;
}
function parseBoundXprobeRequest(rawUrl) {
  let url;
  try { url = new URL(rawUrl, "https://capture.invalid"); } catch { return null; }
  const exactKeys = ["fpVersion", "fpContext", "fpBuild", "fpArtifact", "fpCapture", "fpRequest", "fpParent", "fpAck"];
  if (url.pathname !== "/xprobe" || [...url.searchParams.keys()].sort().join(",") !== exactKeys.slice().sort().join(",")) return null;
  const binding = {
    version: url.searchParams.get("fpVersion"),
    context: url.searchParams.get("fpContext"),
    build: url.searchParams.get("fpBuild"),
    artifactSha256: url.searchParams.get("fpArtifact"),
    captureKey: url.searchParams.get("fpCapture"),
    requestId: url.searchParams.get("fpRequest"),
    parentOrigin: url.searchParams.get("fpParent"),
    acknowledgementSha256: url.searchParams.get("fpAck"),
  };
  let parent;
  try { parent = new URL(binding.parentOrigin); } catch { return null; }
  if (binding.version !== "1" || binding.context !== "cross-origin-iframe"
      || !SHA256_RE.test(binding.build || "") || !SHA256_RE.test(binding.artifactSha256 || "")
      || typeof binding.captureKey !== "string" || binding.captureKey.length < 1 || binding.captureKey.length > 240
      || !/^[A-Za-z0-9_-]{22,240}$/.test(binding.requestId || "")
      || !SHA256_RE.test(binding.acknowledgementSha256 || "")
      || parent.origin !== binding.parentOrigin || !PANEL_PUBLIC_ORIGINS.includes(parent.origin)) return null;
  return binding;
}

// JA4 read from the raw ClientHello, keyed by the client's ephemeral port so
// the HTTP request handler — which sees the same peer — can pair them up.
const pending = new Map();

function h1Responder(res) {
  return (status, headers, body) => {
    res.writeHead(status, { ...headers, connection: "close" });
    res.end(body);
  };
}

function h2Responder(stream, session) {
  return (status, headers, body) => {
    const clean = { ":status": status, ...headers };
    delete clean.connection; // RFC 9113 forbids connection-specific headers
    const empty = body == null || body.length === 0;
    // Node sends END_STREAM with body-forbidden 204 responses. Calling end()
    // again produces ERR_STREAM_WRITE_AFTER_END and used to crash the server.
    if (empty || status === 204 || status === 304) stream.respond(clean, { endStream: true });
    else { stream.respond(clean); stream.end(body); }
    // One request per TLS connection keeps every final capture tied to a fresh
    // ClientHello. GOAWAY is the HTTP/2 equivalent of H1 Connection: close.
    stream.once("close", () => { try { session.close(); } catch {} });
  };
}

async function handleRequest(req, respond) {
    const k = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
    // Cross-origin probe page: serve HTML, don't consume the JA4 pairing.
    if ((req.url || "").split("?")[0] === "/xprobe") {
      pending.delete(k);
      const binding = parseBoundXprobeRequest(req.url || "");
      const xprobeHeaders = {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": FRAME_ANCESTORS_CSP,
        "permissions-policy": "webgpu=(self), keyboard-map=(self), gamepad=(self), accelerometer=(self), gyroscope=(self), magnetometer=(self)",
      };
      if (!binding) { respond(400, xprobeHeaders, "invalid bound-child request"); return; }
      const collector = await getCollector(req.abortSignal);
      if (!collector) { respond(503, xprobeHeaders, "collector unavailable"); return; }
      if (binding.build !== collector.build || binding.artifactSha256 !== collector.artifactSha256) {
        respond(409, xprobeHeaders, "collector binding mismatch"); return;
      }
      let rendered;
      try {
        rendered = renderBoundChildProbe({
          collectorSource: collector.source,
          browserCollectorBuild: collector.build,
          collectorArtifactSha256: collector.artifactSha256,
          captureKey: binding.captureKey,
          requestId: binding.requestId,
          context: binding.context,
          parentOrigin: binding.parentOrigin,
        });
      } catch {
        respond(503, xprobeHeaders, "collector rendering failed"); return;
      }
      if (rendered.acknowledgementSha256 !== binding.acknowledgementSha256) {
        respond(409, xprobeHeaders, "child acknowledgement mismatch"); return;
      }
      respond(200, {
        ...xprobeHeaders,
        "content-type": "text/html; charset=utf-8",
        "x-fingerprint-collector-build": collector.build,
        "x-fingerprint-collector-artifact": collector.artifactSha256,
      }, rendered.html);
      return;
    }
    const entry = pending.get(k); pending.delete(k);
    const fp = entry?.fp || null;
    const token = (() => {
      try { return new URL(req.url, "https://x").searchParams.get("token"); }
      catch { return null; }
    })();

    if (!fp) {
      respond(400, { "content-type": "text/plain; charset=utf-8" }, "не удалось прочитать TLS-рукопожатие");
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
      rawHeadersTyped.push({ name: req.rawHeaders[i], value: req.rawHeaders[i + 1], wireIndex: i / 2 });
    }
    const h = (name) => (req.headers[name] != null ? (Array.isArray(req.headers[name]) ? req.headers[name].join(", ") : String(req.headers[name])) : "absent");
    const hex4 = (n) => ("000" + n.toString(16)).slice(-4);
    const isGrease = (n) => (n & 0x0f0f) === 0x0a0a && (n >>> 8) === (n & 0xff);
    const ra = req.socket.remoteAddress || "";
    const round = (() => { try { return new URL(req.url, "https://x").searchParams.get("round") === "1" ? 1 : 2; } catch { return 2; } })();
    const h2Headers = req.h2 ? analyzeH2RawHeaders(req.rawHeaders) : null;
    const h2Initial = req.h2Initial || null;
    const h2Complete = !!(req.h2 && h2Initial?.status === "complete" && h2Headers?.status === "valid");
    const m = {
      // net-v6 adds HTTP/2 wire SETTINGS + ordered pseudo headers. net-v5 remains
      // a historical partial schema and is never relabelled as complete.
      netSchemaVersion: "net-v6",
      round,                                   // Accept-CH round index (1 = prime, 2 = with hints)
      tlsTyped: {
        // JA3 field 1 is the legacy ClientHello version, not the negotiated
        // supported_versions maximum. Preserve both wire values so the schema
        // can recompute JA3/JA4 instead of trusting precomputed strings.
        tlsRecordVersion: ch.tlsRecordVersion,
        handshakeVersion: ch.handshakeVersion,
        supportedVersionMax: ch.supportedVersionMax,
        ciphers: (ch.ciphers || []), extensions: (ch.extensions || []),
        curves: (ch.curves || []), pointFormats: (ch.pointFormats || []),
        sigAlgs: (ch.sigAlgs || []), alpnOffered: (ch.alpn || []), alpnRaw: (ch.alpnRaw || []),
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
      extensionCount: String((ch.extensions || []).filter((e) => !isGrease(e)).length),
      extensionCountRaw: String((ch.extensions || []).length),
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
      secChUaFormFactors: h("sec-ch-ua-form-factors"),
      // Accept-CH round-trip: this field records which high-entropy hints
      // actually arrived on the explicit second request.
      acceptChAdvertised: "platform-version,arch,bitness,model,full-version-list,wow64,form-factors",
      secFetchSite: h("sec-fetch-site"),
      secFetchMode: h("sec-fetch-mode"),
      secFetchDest: h("sec-fetch-dest"),
      secFetchUser: h("sec-fetch-user"),
      priority: h("priority"),
      // H2: SETTINGS comes from the exact decrypted wire prefix; pseudo-header
      // order comes from Node/nghttp2 rawHeaders (no home-grown HPACK parser).
      http2: req.h2 ? {
        status: h2Complete ? "captured" : "invalid",
        settings: h2Initial?.settings || [],
        settingsOrder: h2Initial?.settingsOrder || [],
        settingsEffective: h2Initial?.effective || {},
        settingsPayloadHex: h2Initial?.payloadHex || null,
        settingsPayloadSha256: h2Initial?.payloadSha256 || null,
        pseudoHeaderOrder: h2Headers?.pseudoHeaderOrder || [],
        headersStatus: h2Headers?.status || "invalid",
        errors: [h2Initial?.error, ...(h2Headers?.errors || [])].filter(Boolean),
      } : { status: "not-negotiated", settings: [], settingsOrder: [], pseudoHeaderOrder: [], errors: [] },
      http2Settings: h2Initial?.settings || [],
      http2PseudoHeaderOrder: h2Headers?.pseudoHeaderOrder || [],
      http3Quic: "not-captured (endpoint is TCP/TLS)",
      webTransport: "not-captured (no WebTransport endpoint)",
      webSocket: "not-captured (no WS endpoint)",
      webrtcStun: "captured in browser webrtc block (host-only, no external STUN)",
      dns: "not-observable at this endpoint",
      // provenance — this layer terminated TLS directly (our capture endpoint),
      // so the JA4/TLS metadata is genuine, not a CDN/proxy re-handshake.
      tlsTerminatedBy: "capture-endpoint",
      parserVersion: "net-v6",
      captureBuild: CAPTURE_BUILD,
      // Source identity and runtime identity are separate on purpose.  Node,
      // OpenSSL and nghttp2 affect the observed TLS/H2 behavior even when the
      // repository bytes are identical, so every record stamps both.
      captureRuntime: {
        node: process.version,
        v8: process.versions.v8,
        openssl: process.versions.openssl,
        nghttp2: process.versions.nghttp2,
      },
    };
    // Round 1 only establishes the Accept-CH policy and is intentionally NOT
    // persisted. Round 2 is the single canonical network record. This prevents
    // two outer `network` records from colliding in the readiness validator.
    const saved = token ? (round === 1 ? true : await postResult(token, m, req.abortSignal)) : false;
    const status = token ? (saved ? (round === 1 ? 204 : 200) : 502) : 400;
    const responseHeaders = {
      "content-type": (token && saved && round === 2) ? "text/html; charset=utf-8" : "text/plain; charset=utf-8",
      "cache-control": "no-store",
      // The browser must be able to observe 200 vs 502. This endpoint carries
      // no credentials and returns only capture acknowledgement; the one-time
      // token still controls which session receives the server-side record.
      "access-control-allow-origin": "*",
      // Accept-CH primes round 2. Critical-CH is deliberately omitted: it may
      // cause an automatic retry and create an untracked third request.
      "accept-ch": "sec-ch-ua-platform-version, sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-model, sec-ch-ua-full-version-list, sec-ch-ua-wow64, sec-ch-ua-form-factors",
    };
    const body = round === 1 && token ? Buffer.alloc(0)
      : (token && saved) ? DONE_PAGE
        : Buffer.from(token ? "панель не сохранила сетевую запись" : "нет токена — открой через панель", "utf8");
    respond(status, responseHeaders, body);
}

// After TLS decryption, peek only the fixed H2 preface + uncompressed SETTINGS,
// restore every byte, then hand the same TLSSocket to Node/nghttp2.
function startH2(socket) {
  const observer = new H2PrefaceObserver();
  const chunks = [];
  let total = 0;
  const onData = (chunk) => {
    chunks.push(chunk); total += chunk.length;
    const result = observer.push(chunk);
    if (result.status === "incomplete") return;
    socket.removeListener("data", onData);
    if (result.status !== "complete") { socket.destroy(); return; }
    socket.pause();
    socket.unshift(Buffer.concat(chunks, total));
    const session = http2.performServerHandshake(socket);
    session.on("error", () => { try { socket.destroy(); } catch {} });
    session.on("stream", (stream, headers, _flags, rawHeaders) => {
      stream.on("error", () => {});
      const requestAbort = new AbortController();
      const abortRequest = () => {
        if (!requestAbort.signal.aborted) requestAbort.abort(new Error("browser-request-closed"));
      };
      stream.once("aborted", abortRequest);
      stream.once("close", abortRequest);
      const req = {
        socket,
        url: String(headers[":path"] || "/"),
        headers,
        rawHeaders,
        httpVersion: "2.0",
        h2: true,
        h2Initial: result,
        abortSignal: requestAbort.signal,
      };
      handleRequest(req, h2Responder(stream, session)).catch(() => {
        try { stream.respond({ ":status": 500 }); stream.end("capture error"); } catch {}
      });
    });
    process.nextTick(() => socket.resume());
  };
  socket.on("data", onData);
}

const h1Server = http.createServer((req, res) => {
  // IncomingMessage properties live on its prototype, so object spread would
  // silently drop socket/url/headers/rawHeaders/httpVersion.
  const requestAbort = new AbortController();
  const abortRequest = () => {
    if (!requestAbort.signal.aborted) requestAbort.abort(new Error("browser-request-closed"));
  };
  req.once("aborted", abortRequest);
  req.socket.once("close", abortRequest);
  handleRequest({
    socket: req.socket,
    url: req.url,
    headers: req.headers,
    rawHeaders: req.rawHeaders,
    httpVersion: req.httpVersion,
    h2: false,
    h2Initial: null,
    abortSignal: requestAbort.signal,
  }, h1Responder(res)).catch(() => {
    if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain", connection: "close" });
    res.end("capture error");
  });
});
h1Server.on("clientError", (_e, sock) => { try { sock.destroy(); } catch {} });

const tlsServer = tls.createServer({
  key: creds.key, cert: creds.cert,
  ALPNProtocols: ["h2", "http/1.1"],
  SNICallback: sniCallback,
});
tlsServer.on("secureConnection", (socket) => {
  if (socket.alpnProtocol === "h2") startH2(socket);
  else {
    socket.pause(); h1Server.emit("connection", socket); process.nextTick(() => socket.resume());
  }
});
tlsServer.on("tlsClientError", (_e, sock) => { try { sock.destroy(); } catch {} });

// Raw TCP front: peek the ClientHello, then hand the socket to the TLS server
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

    // Restore the bytes and hand the socket to the TLS server.
    socket.pause();
    socket.unshift(buf);
    tlsServer.emit("connection", socket);
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
