import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import http2 from "node:http2";
import net from "node:net";
import { once } from "node:events";
import { classifyNetworkSchema } from "../lib/fp-schema.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }

async function freePort() {
  const s = net.createServer();
  await new Promise((resolve, reject) => s.listen(0, "127.0.0.1", (e) => e ? reject(e) : resolve()));
  const port = s.address().port;
  await new Promise((resolve) => s.close(resolve));
  return port;
}

async function h2Get(port, path, extraHeaders = {}) {
  const startedAt = Date.now();
  const client = http2.connect(`https://127.0.0.1:${port}`, {
    rejectUnauthorized: false,
    settings: { headerTableSize: 8192, initialWindowSize: 1_000_000 },
  });
  // Keep a permanent listener because a reset can emit again after the request
  // promise has already rejected and removed its one-shot listener.
  client.on("error", () => {});
  const response = await new Promise((resolve, reject) => {
    client.once("error", reject);
    const req = client.request({
      ":method": "GET", ":authority": `127.0.0.1:${port}`,
      ":scheme": "https", ":path": path,
      origin: "https://panel.test", "user-agent": "capture-integration-test",
      ...extraHeaders,
    });
    req.on("error", () => {});
    let headers, body = "";
    req.once("response", (h) => { headers = h; });
    req.setEncoding("utf8");
    req.on("data", (chunk) => { body += chunk; });
    req.once("end", () => resolve({ headers, body, elapsedMs: Date.now() - startedAt }));
    req.once("error", reject);
    req.end(); req.resume();
  });
  client.close();
  return response;
}

async function checkRejectedStartup(env) {
  const child = spawn(process.execPath, ["--experimental-strip-types", "scripts/capture-server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, PORT: String(await freePort()), CAPTURE_SECRET: "startup-test", NODE_NO_WARNINGS: "1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (x) => { output += x; });
  child.stderr.on("data", (x) => { output += x; });
  const outcome = await Promise.race([
    once(child, "exit").then(([code]) => ({ code, output })),
    new Promise((resolve) => setTimeout(() => resolve({ code: null, output }), 2_000)),
  ]);
  if (outcome.code == null) {
    child.kill("SIGTERM");
    await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 1_000))]);
  }
  return { ...outcome, output };
}

const missingOrigins = await checkRejectedStartup({
  PANEL_PUBLIC_ORIGINS: "", CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "1",
});
ok("capture refuses to start without PANEL_PUBLIC_ORIGINS", missingOrigins.code !== 0 && /PANEL_PUBLIC_ORIGINS/.test(missingOrigins.output));
const invalidOrigins = await checkRejectedStartup({
  PANEL_PUBLIC_ORIGINS: "https://good.example/path", CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "1",
});
ok("capture refuses non-origin frame-ancestor values", invalidOrigins.code !== 0 && /PANEL_PUBLIC_ORIGINS/.test(invalidOrigins.output));
const insecurePublicOrigin = await checkRejectedStartup({
  PANEL_URL: "http://127.0.0.1:3400", PANEL_PUBLIC_ORIGINS: "http://panel.example",
  CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "1",
});
ok("capture refuses non-loopback HTTP public origins",
  insecurePublicOrigin.code !== 0 && /PANEL_PUBLIC_ORIGINS/.test(insecurePublicOrigin.output));
const unsafePanelUrl = await checkRejectedStartup({
  PANEL_URL: "http://attacker.example/path", PANEL_PUBLIC_ORIGINS: "https://panel.test",
  CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "1",
});
ok("capture never sends its shared secret to an arbitrary/inexact panel URL",
  unsafePanelUrl.code !== 0 && /PANEL_URL/.test(unsafePanelUrl.output));
const noCertificate = await checkRejectedStartup({
  PANEL_PUBLIC_ORIGINS: "https://panel.test", CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "",
});
ok("capture fails closed without a production certificate",
  noCertificate.code !== 0 && /certificate|CERT_FILE/i.test(noCertificate.output));
const halfCertificate = await checkRejectedStartup({
  PANEL_PUBLIC_ORIGINS: "https://panel.test", CERT_FILE: "/definitely/missing.pem", KEY_FILE: "",
  ALLOW_SELF_SIGNED_FOR_TESTS: "1",
});
ok("capture rejects a half-configured certificate pair even in test mode",
  halfCertificate.code !== 0 && /CERT_FILE.*KEY_FILE|certificate pair/i.test(halfCertificate.output));
const missingSniCertificate = await checkRejectedStartup({
  PANEL_PUBLIC_ORIGINS: "https://panel.test", CERT_FILE: "", KEY_FILE: "",
  ALLOW_SELF_SIGNED_FOR_TESTS: "1", TLS_DOMAINS: "missing-cert.invalid",
});
ok("declared SNI domains fail startup when their certificate cannot load",
  missingSniCertificate.code !== 0 && /SNI certificate/i.test(missingSniCertificate.output));

const panelPort = await freePort();
const capturePort = await freePort();
const posted = [];
const descriptorRequests = [];
const collectorRequests = [];
const collectorSource = "self.LinkageProbe={collect:async function(c){return {_context:c,marker:'bound-collector'}}};";
const artifactSha256 = createHash("sha256").update(collectorSource).digest("hex");
const panelState = {
  buildMode: "valid",
  buildDelayMs: 0,
  collectorDelayMs: 0,
  postDelayMs: 0,
  collectorSource,
  artifactSha256,
  browserCollectorBuild: "b".repeat(64),
  descriptorSequence: [],
  collectorSequence: [],
};
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
  }
  return value;
}
let childRequestSequence = 0;
function boundXprobePath({
  build = panelState.browserCollectorBuild,
  artifactSha256: artifact = panelState.artifactSha256,
  captureKey = "pair-1:plain",
  requestId = (++childRequestSequence).toString(16).padStart(32, "0"),
  parentOrigin = "https://panel.test",
  acknowledgementSha256,
} = {}) {
  const core = {
    protocol: "fingerprint-bound-child",
    handshakeVersion: 1,
    context: "cross-origin-iframe",
    collectorBuild: build,
    collectorArtifactSha256: artifact,
    captureKey,
    requestId,
    parentOrigin,
  };
  const ack = acknowledgementSha256 || createHash("sha256")
    .update(JSON.stringify(canonical(core)))
    .digest("hex");
  const query = new URLSearchParams({
    fpVersion: "1",
    fpContext: core.context,
    fpBuild: build,
    fpArtifact: artifact,
    fpCapture: captureKey,
    fpRequest: requestId,
    fpParent: parentOrigin,
    fpAck: ack,
  });
  return `/xprobe?${query}`;
}
function later(ms, fn) { if (ms > 0) setTimeout(fn, ms); else fn(); }
const panel = http.createServer((req, res) => {
  if (req.url === "/api/fingerprint/collector-descriptor" && req.method === "GET") {
    descriptorRequests.push({ secret: req.headers["x-capture-secret"] });
    const queuedDescriptor = panelState.descriptorSequence.shift();
    later(panelState.buildDelayMs, () => {
      if (res.destroyed) return;
      if (panelState.buildMode === "unavailable") { res.writeHead(503); res.end("unavailable"); return; }
      if (panelState.buildMode === "stalled-body") {
        res.writeHead(200, { "content-type": "application/json" });
        res.write('{"browserCollectorBuild":');
        return;
      }
      if (panelState.buildMode === "oversized-body") {
        // Deliberately omit Content-Length: this proves the streaming byte
        // counter, rather than only a header pre-check, terminates the read.
        res.writeHead(200, { "content-type": "application/json" });
        res.end("x".repeat(70 * 1024));
        return;
      }
      const browserCollectorBuild = queuedDescriptor?.browserCollectorBuild
        ?? (panelState.buildMode === "fake-label" ? "v4.4" : panelState.browserCollectorBuild);
      const responseArtifactSha256 = queuedDescriptor?.artifactSha256 ?? panelState.artifactSha256;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ browserCollectorBuild, browserCollectorArtifactSha256: responseArtifactSha256 }));
    });
    return;
  }
  if (req.url === "/fingerprint/collector" && req.method === "GET") {
    collectorRequests.push({ secret: req.headers["x-capture-secret"] });
    const queuedCollector = panelState.collectorSequence.shift();
    later(panelState.collectorDelayMs, () => {
      if (res.destroyed) return;
      res.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
      res.end(queuedCollector ?? panelState.collectorSource);
    });
    return;
  }
  if (req.url !== "/api/fingerprint/net-result" || req.method !== "POST") {
    res.writeHead(404); res.end(); return;
  }
  let raw = "";
  req.setEncoding("utf8"); req.on("data", (x) => { raw += x; });
  req.on("end", () => {
    later(panelState.postDelayMs, () => {
      // A timed-out/aborted capture callback must not turn into a late write.
      // Production persistence must enforce the same deadline before commit.
      if (res.destroyed || Date.now() > Number(req.headers["x-capture-deadline"] || 0)) return;
      try {
        posted.push({
          secret: req.headers["x-capture-secret"],
          deadline: req.headers["x-capture-deadline"],
          idempotencyKey: req.headers["x-idempotency-key"],
          body: JSON.parse(raw),
        });
      }
      catch { res.writeHead(400); res.end(); return; }
      res.writeHead(204); res.end();
    });
  });
});
await new Promise((resolve, reject) => panel.listen(panelPort, "127.0.0.1", (e) => e ? reject(e) : resolve()));

const child = spawn(process.execPath, ["--experimental-strip-types", "scripts/capture-server.mjs"], {
  cwd: new URL("..", import.meta.url),
  env: {
    ...process.env, PORT: String(capturePort),
    PANEL_URL: `http://127.0.0.1:${panelPort}`,
    PANEL_PUBLIC_ORIGINS: `https://panel.test,http://127.0.0.1:${panelPort}`,
    PANEL_FETCH_TIMEOUT_MS: "120",
    CAPTURE_SECRET: "integration-secret",
    CERT_FILE: "", KEY_FILE: "", ALLOW_SELF_SIGNED_FOR_TESTS: "1", TLS_DOMAINS: "",
    NODE_NO_WARNINGS: "1",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let childOut = "";
child.stdout.on("data", (x) => { childOut += x; if (process.env.DEBUG_CAPTURE) process.stderr.write(x); });
child.stderr.on("data", (x) => { childOut += x; if (process.env.DEBUG_CAPTURE) process.stderr.write(x); });

try {
  await Promise.race([
    (async () => { while (!childOut.includes("приёмник JA4 слушает")) await new Promise((r) => setTimeout(r, 10)); })(),
    new Promise((_, reject) => setTimeout(() => reject(new Error("capture server start timeout: " + childOut)), 10_000)),
    once(child, "exit").then(([code]) => { throw new Error(`capture server exited ${code}: ${childOut}`); }),
  ]);

  const initialXprobePath = boundXprobePath();
  const malformedXprobe = await h2Get(capturePort, "/xprobe");
  ok("xprobe rejects an unbound legacy request", malformedXprobe.headers[":status"] === 400);
  const xprobe = await h2Get(capturePort, initialXprobePath);
  ok("xprobe serves only the source whose artifact hash matches the build descriptor",
    xprobe.headers[":status"] === 200 && xprobe.body.includes("bound-collector"));
  ok("capture authenticates immutable descriptor and collector fetches",
    descriptorRequests.length === 1 && collectorRequests.length === 1
      && descriptorRequests[0].secret === "integration-secret"
      && collectorRequests[0].secret === "integration-secret");
  ok("xprobe frame-ancestors is built only from the validated public-origin allowlist",
    xprobe.headers["content-security-policy"] === `default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors https://panel.test http://127.0.0.1:${panelPort}`);
  ok("xprobe delegates measured features explicitly",
    /keyboard-map=\(self\)/.test(xprobe.headers["permissions-policy"] || ""));
  ok("xprobe emits the build/capture/request-bound child handshake",
    xprobe.body.includes("__fpBoundChild") && xprobe.body.includes('"collectorBuild":"' + panelState.browserCollectorBuild + '"')
      && xprobe.body.includes('"collectorArtifactSha256":"' + panelState.artifactSha256 + '"')
      && xprobe.body.includes('"parentOrigin":"https://panel.test"')
      && !xprobe.body.includes("postMessage(envelope,'*')"));
  const badAckPath = boundXprobePath({ acknowledgementSha256: "f".repeat(64) });
  const badAck = await h2Get(capturePort, badAckPath);
  ok("xprobe rejects a URL whose acknowledgement does not bind its exact fields", badAck.headers[":status"] === 409);

  panelState.buildMode = "fake-label";
  const staleDenied = await h2Get(capturePort, initialXprobePath);
  ok("an invalid build label fails closed instead of serving stale cached source", staleDenied.headers[":status"] === 503);
  panelState.buildMode = "unavailable";
  const unavailableDenied = await h2Get(capturePort, initialXprobePath);
  ok("an unavailable build endpoint fails closed instead of serving stale cached source", unavailableDenied.headers[":status"] === 503);
  panelState.buildMode = "stalled-body";
  const stalledBuildBody = await h2Get(capturePort, initialXprobePath);
  ok("panel timeout covers response-body consumption, not only response headers",
    stalledBuildBody.headers[":status"] === 503 && stalledBuildBody.elapsedMs < 1_000);
  panelState.buildMode = "oversized-body";
  const oversizedBuildBody = await h2Get(capturePort, initialXprobePath);
  ok("panel response bodies are byte-capped even without Content-Length",
    oversizedBuildBody.headers[":status"] === 503 && oversizedBuildBody.elapsedMs < 1_000);
  panelState.buildMode = "valid";
  panelState.artifactSha256 = "c".repeat(64);
  const sourceMismatch = await h2Get(capturePort, initialXprobePath);
  ok("collector source hash mismatch fails closed", sourceMismatch.headers[":status"] === 503);
  panelState.artifactSha256 = artifactSha256;
  panelState.buildDelayMs = 350;
  const boundedBuild = await h2Get(capturePort, initialXprobePath);
  ok("panel build fetch is bounded and fails closed", boundedBuild.headers[":status"] === 503 && boundedBuild.elapsedMs < 1_000);
  panelState.buildDelayMs = 0;
  panelState.collectorSource += "\n";
  panelState.artifactSha256 = createHash("sha256").update(panelState.collectorSource).digest("hex");
  const equivocationDenied = await h2Get(capturePort, initialXprobePath);
  ok("one collector build cannot be rebound to different artifact bytes",
    equivocationDenied.headers[":status"] === 503);
  panelState.browserCollectorBuild = "d".repeat(64);
  const nextBuildPath = boundXprobePath();
  panelState.collectorDelayMs = 350;
  const boundedCollector = await h2Get(capturePort, nextBuildPath);
  ok("panel collector-source fetch is bounded and fails closed", boundedCollector.headers[":status"] === 503 && boundedCollector.elapsedMs < 1_000);
  panelState.collectorDelayMs = 0;
  const nextBuild = await h2Get(capturePort, nextBuildPath);
  ok("new artifact bytes are accepted only under a distinct verified build",
    nextBuild.headers[":status"] === 200 && nextBuild.body.includes("bound-collector"));

  // Two first-seen requests for one build used to race across the awaited
  // collector body read and could bind two different artifacts. Exactly one
  // contender must win; the other must fail closed.
  const raceBuild = "e".repeat(64);
  const raceSourceA = "self.LinkageProbe={collect:async c=>({_context:c,race:'a'})};";
  const raceSourceB = "self.LinkageProbe={collect:async c=>({_context:c,race:'b'})};";
  panelState.descriptorSequence.push(
    { browserCollectorBuild: raceBuild, artifactSha256: createHash("sha256").update(raceSourceA).digest("hex") },
    { browserCollectorBuild: raceBuild, artifactSha256: createHash("sha256").update(raceSourceB).digest("hex") },
  );
  panelState.collectorSequence.push(raceSourceA, raceSourceB);
  const raceResults = await Promise.all([
    h2Get(capturePort, boundXprobePath({ build: raceBuild, artifactSha256: createHash("sha256").update(raceSourceA).digest("hex") })),
    h2Get(capturePort, boundXprobePath({ build: raceBuild, artifactSha256: createHash("sha256").update(raceSourceB).digest("hex") })),
  ]);
  const raceAccepted = raceResults.filter((result) => result.headers[":status"] === 200).length;
  ok("concurrent first-seen requests cannot rebind one build to two artifacts",
    raceAccepted <= 1
      && raceResults.every((result) => result.headers[":status"] === 200 || result.headers[":status"] === 503));

  const prime = await h2Get(capturePort, "/?token=one-time&round=1");
  ok("round 1 returns acknowledged 204", prime.headers[":status"] === 204);
  ok("round 1 advertises the complete reviewed UA-CH set including form factors",
    String(prime.headers["accept-ch"] || "").toLowerCase().includes("sec-ch-ua-form-factors"));
  ok("round 1 sends readable CORS acknowledgement", prime.headers["access-control-allow-origin"] === "*");
  ok("round 1 is not persisted", posted.length === 0);

  const highEntropyHints = {
    "sec-ch-ua": `"Chromium";v="140", "Not=A?Brand";v="24"`,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": `"macOS"`,
    "sec-ch-ua-platform-version": `"15.6.0"`,
    "sec-ch-ua-arch": `"arm"`,
    "sec-ch-ua-bitness": `"64"`,
    "sec-ch-ua-model": `""`,
    "sec-ch-ua-full-version-list": `"Chromium";v="140.0.7339.0", "Not=A?Brand";v="24.0.0.0"`,
    "sec-ch-ua-wow64": "?0",
    "sec-ch-ua-form-factors": `"Desktop"`,
  };
  const final = await h2Get(capturePort, "/?token=one-time&round=2", highEntropyHints);
  ok("round 2 returns 200 only after panel persistence", final.headers[":status"] === 200 && posted.length === 1);
  ok("capture authenticates its panel callback", posted[0]?.secret === "integration-secret" && posted[0]?.body?.token === "one-time");
  ok("persistence callback binds a deadline and idempotency key in headers and body",
    posted[0]?.deadline === String(posted[0]?.body?.delivery?.deadlineAt)
      && /^[0-9a-f]{64}$/.test(posted[0]?.idempotencyKey || "")
      && posted[0]?.idempotencyKey === posted[0]?.body?.delivery?.idempotencyKey);
  const record = posted[0]?.body?.m;
  ok("capture computes a full executable-tree build id at runtime", /^[0-9a-f]{64}$/.test(record?.captureBuild || ""));
  ok("capture preserves the TLS versions needed to recompute JA3/JA4",
    Number.isInteger(record?.tlsTyped?.handshakeVersion)
      && Number.isInteger(record?.tlsTyped?.tlsRecordVersion)
      && (record?.tlsTyped?.supportedVersionMax === null || Number.isInteger(record?.tlsTyped?.supportedVersionMax)));
  ok("live TLS/H2 record satisfies net-v6 CURRENT schema", classifyNetworkSchema(record) === "CURRENT");
  ok("initial SETTINGS and their exact order are captured", record?.http2?.settings?.length > 0
    && record.http2.settingsOrder.join(",") === record.http2.settings.map((x) => x.id).join(","));
  ok("raw SETTINGS payload is persisted for semantic hash verification",
    typeof record?.http2?.settingsPayloadHex === "string" && record.http2.settingsPayloadHex.length === record.http2.settings.length * 12);
  ok("pseudo-header order comes from the decoded request", record?.http2?.pseudoHeaderOrder?.join(",") === ":method,:authority,:scheme,:path");
  ok("round 2 persists observed high-entropy Client Hints rather than absent placeholders",
    record?.secChUaPlatformVersion === highEntropyHints["sec-ch-ua-platform-version"]
      && record?.secChUaArch === highEntropyHints["sec-ch-ua-arch"]
      && record?.secChUaBitness === highEntropyHints["sec-ch-ua-bitness"]
      && record?.secChUaModel === highEntropyHints["sec-ch-ua-model"]
      && record?.secChUaFullVersionList === highEntropyHints["sec-ch-ua-full-version-list"]
      && record?.secChUaWow64 === highEntropyHints["sec-ch-ua-wow64"]
      && record?.secChUaFormFactors === highEntropyHints["sec-ch-ua-form-factors"]);

  panelState.postDelayMs = 350;
  const timedOut = await h2Get(capturePort, "/?token=timeout-token&round=2", highEntropyHints);
  ok("panel persistence callback is bounded and returns failure instead of late success",
    timedOut.headers[":status"] === 502 && timedOut.elapsedMs < 1_000);
  await new Promise((resolve) => setTimeout(resolve, 400));
  ok("expired callback deadline prevents a ghost write in the panel contract", posted.length === 1);
} catch (error) {
  error.message += `\n--- capture-server output ---\n${childOut}`;
  throw error;
} finally {
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
  await new Promise((resolve) => panel.close(resolve));
}

console.log(`\nfp-capture: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
