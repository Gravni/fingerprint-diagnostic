// Regression tests for the comparator rule engine (Codex v4 §Компаратор).
import { compareMeasurements, summarize } from "../lib/fp-compare.mjs";
import { isExpectedTarget, classifyPath } from "../lib/fp-expect.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }
const r = (path, o = {}) => Object.assign({ path, context: "main-frame", phase: "passive", status: "ok", valueType: "string", value: "x", error: null, meta: {} }, o);
const verdictOf = (rows, path) => (rows.find((x) => x.path === path) || {}).verdict;

// no profile → only same/different/plain-only/anti-only/unresolved; NEVER leaked/masked
{
  const plain = [
    r("a.same", { value: "1" }),
    r("a.diff", { value: "1" }),
    r("a.err", { status: "error", valueType: null, value: null, error: { name: "E" } }),
    r("a.unavail", { status: "unavailable-in-context", valueType: "null", value: null }),
    r("a.ponly", { value: "p" }),
  ];
  const anti = [
    r("a.same", { value: "1" }),
    r("a.diff", { value: "2" }),
    r("a.err", { value: "real" }),                 // plain errored, anti ok
    r("a.unavail", { value: "real" }),             // plain unavailable, anti ok
    r("a.aonly", { value: "a" }),
  ];
  const rows = compareMeasurements(plain, anti, { hasProfile: false });
  ok("identical → same", verdictOf(rows, "a.same") === "same");
  ok("differ (no profile) → different", verdictOf(rows, "a.diff") === "different");
  ok("plain error + anti ok → unresolved (NOT leaked)", verdictOf(rows, "a.err") === "unresolved");
  ok("plain unavailable → unresolved (NOT masked)", verdictOf(rows, "a.unavail") === "unresolved");
  ok("only in plain → plain-only", verdictOf(rows, "a.ponly") === "plain-only");
  ok("only in anti → anti-only", verdictOf(rows, "a.aonly") === "anti-only");
  const c = summarize(rows);
  ok("NO leaked without profile", !c.leaked);
  ok("NO masked without profile", !c.masked);
}

// with a profile that protects `canvas.hash`: identical=leaked, differ=masked
{
  const plain = [r("canvas.hash", { value: "H1" }), r("nav.ua", { value: "UA" })];
  const anti = [r("canvas.hash", { value: "H2" }), r("nav.ua", { value: "UA" })];
  const rows = compareMeasurements(plain, anti, {
    hasProfile: true,
    profileProtects: (path) => path === "canvas.hash",
  });
  ok("protected + differ → masked", verdictOf(rows, "canvas.hash") === "masked");
  ok("unprotected identical → same (not leaked)", verdictOf(rows, "nav.ua") === "same");
}
{
  // protected but identical → leaked (should have changed, didn't)
  const rows = compareMeasurements([r("canvas.hash", { value: "H" })], [r("canvas.hash", { value: "H" })], {
    hasProfile: true, profileProtects: () => true,
  });
  ok("protected + identical → leaked", verdictOf(rows, "canvas.hash") === "leaked");
}
{
  // unavailable on a PROTECTED path is still unresolved, never leaked/masked
  const rows = compareMeasurements(
    [r("canvas.hash", { status: "unavailable-in-context", valueType: "null", value: null })],
    [r("canvas.hash", { value: "H2" })],
    { hasProfile: true, profileProtects: () => true },
  );
  ok("protected but unavailable → unresolved", verdictOf(rows, "canvas.hash") === "unresolved");
}
{
  // volatile paths surfaced separately, never masking
  const rows = compareMeasurements([r("window.innerWidth", { value: "1000" })], [r("window.innerWidth", { value: "1200" })], {
    hasProfile: true, profileProtects: () => true, volatile: (p) => p === "window.innerWidth",
  });
  ok("volatile → volatile (not masked)", verdictOf(rows, "window.innerWidth") === "volatile");
}

// ---- #16 expectation registry: only TARGET paths of a spoofed vector ---------
ok("canvas.pixelFnv IS a canvas target", isExpectedTarget("canvas.pixelFnv", "canvas"));
ok("canvas.available NOT a target", !isExpectedTarget("canvas.available", "canvas"));
ok("webgpu.vendor IS a webgpu target", isExpectedTarget("webgpu.vendor", "webgpu"));
ok("webgpu.isFallback NOT a target (undefined can't leak)", !isExpectedTarget("webgpu.isFallback", "webgpu"));
ok("webgpu.status NOT a target", !isExpectedTarget("webgpu.status", "webgpu"));
ok("webgl.unmaskedRenderer IS a target", isExpectedTarget("webgl1.unmaskedRenderer", "webgl"));
ok("fonts.hash IS a target", isExpectedTarget("fonts.hash", "fonts"));
ok("fonts.available NOT a target", !isExpectedTarget("fonts.available", "fonts"));
ok("permissioned.geo.latitude IS a geolocation target", isExpectedTarget("permissioned.geo.latitude", "geolocation"));
ok("direct canvas has no expected-change targets", !isExpectedTarget("canvas.pixelFnv", "canvas", "direct"));
ok("direct WebGPU has no expected-change targets", !isExpectedTarget("webgpu.vendor", "webgpu", "direct"));
ok("real fonts have no expected-change targets", !isExpectedTarget("fonts.hash", "fonts", "real"));
ok("timezone off has no expected-change targets", !isExpectedTarget("locale.resolvedTZ", "timezone", "off"));
ok("WebGL noise does not promise an identity rewrite", !isExpectedTarget("webgl.webgl2.unmaskedVendor", "webgl", "noise"));
{
  // Enabled webgpu vector, but the differing path is NOT a target → `different`,
  // never masked; and an identical non-target → `unchanged`, never leaked.
  const target = (path) => isExpectedTarget(path, "webgpu"); // vector is "on"
  const rows = compareMeasurements(
    [r("webgpu.isFallback", { valueType: "undefined", value: null }), r("webgpu.vendor", { value: "nvidia" })],
    [r("webgpu.isFallback", { valueType: "undefined", value: null }), r("webgpu.vendor", { value: "apple" })],
    { hasProfile: true, profileProtects: (p) => target(p) },
  );
  ok("webgpu.isFallback identical (non-target) → unchanged, NOT leaked", verdictOf(rows, "webgpu.isFallback") === "same");
  ok("webgpu.vendor differs (target) → masked", verdictOf(rows, "webgpu.vendor") === "masked");
}

// ---- #6 CONTRACT: every emitted vector path is target-or-excluded ----------
ok("canvas.pixelFnv IS a target (was unrecognised)", classifyPath("canvas.pixelFnv") === "target");
ok("canvas.pixelSha256 IS a target", classifyPath("canvas.pixelSha256") === "target");
ok("canvas.repeats IS a target", classifyPath("canvas.repeats") === "target");
ok("webgpu.render.hash IS a target (was unrecognised)", classifyPath("webgpu.render.hash") === "target");
ok("WebGPU compute SHA-256 IS a target", classifyPath("webgpu.compute.sha256") === "target");
ok("WebGPU render SHA-256 IS a target", classifyPath("webgpu.render.sha256") === "target");
ok("webgl render.fnv IS a target", classifyPath("webgl1.render.fnv") === "target");
ok("webgl unmaskedRenderer IS a target", classifyPath("webgl2.unmaskedRenderer") === "target");
ok("actual emitted WebGL SHA-256 IS a target", classifyPath("webgl.webgl2.render.sha256") === "target");
ok("WebGL SHA-256 repeats ARE a target", classifyPath("webgl.webgl2.render.sha256Repeats") === "target");
ok("WebGL FNV repeats ARE a target", classifyPath("webgl.webgl.render.fnvRepeats") === "target");
ok("audio offline SHA-256 IS a target", classifyPath("audio.offline.sha256") === "target");
ok("audio offline FNV IS a target", classifyPath("audio.offline.fnv") === "target");
ok("audio SHA-256 repeats ARE a target", classifyPath("audio.offline.sha256Repeats") === "target");
ok("canvas.width is EXCLUDED metadata", classifyPath("canvas.width") === "excluded");
ok("webgpu.isFallback EXCLUDED (can't leak)", classifyPath("webgpu.isFallback") === "excluded");
ok("WebGPU digest algorithm is EXCLUDED metadata", classifyPath("webgpu.render.hashAlgorithm") === "excluded");
ok("WebGPU render geometry is EXCLUDED metadata", classifyPath("webgpu.render.width") === "excluded");
ok("WebGL render geometry is EXCLUDED metadata", classifyPath("webgl.webgl2.render.width") === "excluded");
ok("audio sample count is EXCLUDED metadata", classifyPath("audio.offline.sampleCount") === "excluded");
ok("audio realtime observation is EXCLUDED metadata", classifyPath("audio.realtime.baseLatency") === "excluded");
ok("unknown future WebGPU evidence is deliberately unclassified", classifyPath("webgpu.render.driverSecret") === "UNCLASSIFIED:webgpu");
ok("unknown future WebGL evidence is deliberately unclassified", classifyPath("webgl.webgl2.render.driverSecret") === "UNCLASSIFIED:webgl");
ok("unknown future audio evidence is deliberately unclassified", classifyPath("audio.realtime.sinkId") === "UNCLASSIFIED:audio");
{
  // Extract every literal spoofable-vector path plus every dynamic WebGL and
  // WebGPU path emitted by the collector. The two genuinely key-driven families
  // (WebGL params/precision and ClientRects text metrics) are represented too.
  // A newly emitted field therefore fails until its target/exclusion semantics
  // are consciously added to the registry (Codex v4.3 #6).
  const here = dirname(fileURLToPath(import.meta.url));
  const probe = readFileSync(join(here, "../assets/fingerprint-probe.html"), "utf8");
  const lit = [...probe.matchAll(/M\('((?:canvas|webgpu|audio|fonts|clientRects|mediaDevices|locale)\.[^']*)'/g)]
    .map((m) => m[1]).filter((p) => !p.endsWith("."));
  const webglSuffixes = [...probe.matchAll(/M\('webgl\.'\+name\+'\.([^']+)'/g)]
    .map((m) => m[1]).filter((suffix) => !suffix.endsWith("."));
  webglSuffixes.push("params.MAX_TEXTURE_SIZE", "precision.VERTEX_SHADER.HIGH_FLOAT");
  const webgl = webglSuffixes.flatMap((suffix) => ["webgl.webgl." + suffix, "webgl.webgl2." + suffix]);
  const gpuEmitter = /function emitGpuMeasurements\(prefix,result\)\{[\s\S]*?\[([^\]]+)\]\.forEach/.exec(probe);
  const gpuSuffixes = gpuEmitter ? [...gpuEmitter[1].matchAll(/'([^']+)'/g)].map((m) => m[1]) : [];
  ok("contract extractor found the dynamic WebGPU emitter", gpuSuffixes.length > 0);
  const gpuDynamic = gpuSuffixes.flatMap((suffix) => ["webgpu.compute." + suffix, "webgpu.render." + suffix]);
  const geoDynamic = [
    "latitude", "longitude", "accuracy", "altitude", "altitudeAccuracy",
    "heading", "speed", "timestamp", "coarseBucket",
  ].map((suffix) => "permissioned.geo." + suffix);
  const all = [...new Set([...lit, ...webgl, ...gpuDynamic, ...geoDynamic, "clientRects.tm.width"])];
  const uncl = all.filter((p) => classifyPath(p).indexOf("UNCLASSIFIED") === 0);
  if (uncl.length) console.log("   UNCLASSIFIED paths:", uncl.join(", "));
  ok(`contract: all ${all.length} emitted vector paths are target-or-excluded`, uncl.length === 0);
}
// mode-aware: geolocation 'prompt' reads the REAL location → not a spoof target
ok("geo 'prompt' mode: lat/lon NOT a target", !isExpectedTarget("permissioned.geo.latitude", "geolocation", "prompt"));
ok("geo 'manual' mode: lat/lon IS a target", isExpectedTarget("permissioned.geo.latitude", "geolocation", "manual"));

// ---- defensive comparison: never silently collapse duplicate raw rows ------
{
  const rows = compareMeasurements(
    [r("x", { value: "first" }), r("x", { value: "second" })],
    [r("x", { value: "first" })],
  );
  ok("duplicate key becomes unresolved, never last-write-wins",
    rows.length === 1 && rows[0].verdict === "unresolved" && rows[0].reason === "duplicate measurement key"
      && rows[0].plainCount === 2 && rows[0].antiCount === 1);
}
{
  const rows = compareMeasurements(
    [r("x", { context: "main-frame", value: "a" }), r("x", { context: "iframe", value: "b" })],
    [r("x", { context: "main-frame", value: "a" }), r("x", { context: "iframe", value: "b" })],
  );
  ok("same path across contexts remains two independent rows", rows.length === 2 && rows.every((x) => x.verdict === "same"));
}
{
  const rows = compareMeasurements(
    [r("x", { valueType: "object", value: { a: 1, b: 2 } })],
    [r("x", { valueType: "object", value: { b: 2, a: 1 } })],
  );
  ok("object insertion order is not a value difference", rows.length === 1 && rows[0].verdict === "same");
}
{
  // `__proto__` must remain an ordinary data key. Assigning it to a normal
  // object mutates that object's prototype and used to erase the actual value
  // from canonical JSON, making two different encoded objects compare equal.
  const leftProps = Object.create(null), rightProps = Object.create(null);
  leftProps.__proto__ = { valueType: "string", value: "plain" };
  rightProps.__proto__ = { valueType: "string", value: "anti" };
  const rows = compareMeasurements(
    [r("x", { valueType: "object", value: { __ctor: "Object", props: leftProps } })],
    [r("x", { valueType: "object", value: { __ctor: "Object", props: rightProps } })],
  );
  ok("prototype-named data keys survive canonical comparison",
    rows.length === 1 && rows[0].verdict === "different");
}
{
  const rows = compareMeasurements(
    [r("x", { valueType: "array", value: [1, 2], meta: { count: 9000 } })],
    [r("x", { valueType: "array", value: [1, 2], meta: { count: 10000 } })],
  );
  ok("original array count participates in equality", rows.length === 1 && rows[0].verdict === "different");
  ok("different capped-array counts remain visible on both sides",
    rows[0].plain.meta.count === 9000 && rows[0].anti.meta.count === 10000);
}
{
  const plainError = { name: "TypeError", message: "plain failed", stack: "plain-stack" };
  const antiError = { name: "SecurityError", message: "anti denied", stack: "anti-stack" };
  const rows = compareMeasurements(
    [r("x", { status: "error", valueType: null, value: null, error: plainError })],
    [r("x", { status: "error", valueType: null, value: null, error: antiError })],
  );
  ok("non-ok error records remain unresolved", rows.length === 1 && rows[0].verdict === "unresolved");
  ok("different structured errors remain visible on both sides",
    JSON.stringify(rows[0].plain.error) === JSON.stringify(plainError)
      && JSON.stringify(rows[0].anti.error) === JSON.stringify(antiError));
}
{
  const blob = (sha) => ({ __blobRef: {
    kind: "string", sha256: sha.repeat(64), fnv: "deadbeef", length: 20000,
    preview: "prefix", complete: true, hashScope: "content", stored: false,
  } });
  const rows = compareMeasurements(
    [r("x", { valueType: "string", value: blob("a") })],
    [r("x", { valueType: "string", value: blob("b") })],
  );
  ok("different blob references compare as different", rows.length === 1 && rows[0].verdict === "different");
  ok("blob reference identity remains visible in each side value",
    rows[0].plain.value.__blobRef.sha256 === "a".repeat(64)
      && rows[0].anti.value.__blobRef.sha256 === "b".repeat(64));
}
{
  const incomplete = { __blobRef: {
    kind: "string", sha256: "a".repeat(64), fnv: "deadbeef", length: 20000,
    preview: null, complete: false, hashScope: "marker", stored: false,
  } };
  const rows = compareMeasurements(
    [r("x", { valueType: "string", value: incomplete })],
    [r("x", { valueType: "string", value: incomplete })],
  );
  ok("identical incomplete markers remain unresolved, never same",
    rows.length === 1 && rows[0].verdict === "unresolved" && rows[0].reason === "incomplete encoded value");
}
{
  const rows = compareMeasurements(
    [r("x", { valueType: "number", value: 0, meta: { special: "-0", durationMs: 1.25 } })],
    [r("x", { valueType: "number", value: null, meta: { special: "NaN", durationMs: 2.5 } })],
  );
  ok("special-number metadata remains structured and legacy alias remains available",
    rows[0].plain.meta.special === "-0" && rows[0].anti.meta.special === "NaN"
      && rows[0].plain.special === "-0" && rows[0].anti.special === "NaN");
  ok("non-identity measurement metadata remains available for diagnostics",
    rows[0].plain.meta.durationMs === 1.25 && rows[0].anti.meta.durationMs === 2.5);
}

console.log(`\nfp-compare: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
