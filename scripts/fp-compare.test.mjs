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
ok("webgl render.fnv IS a target", classifyPath("webgl1.render.fnv") === "target");
ok("webgl unmaskedRenderer IS a target", classifyPath("webgl2.unmaskedRenderer") === "target");
ok("canvas.width is EXCLUDED metadata", classifyPath("canvas.width") === "excluded");
ok("webgpu.isFallback EXCLUDED (can't leak)", classifyPath("webgpu.isFallback") === "excluded");
ok("audio.offline.bufLen EXCLUDED", classifyPath("audio.offline.bufLen") === "excluded");
{
  // Extract EVERY literal spoofable-vector path the collector emits + representative
  // dynamic webgl paths; assert none is UNCLASSIFIED (Codex v4.3 #6).
  const here = dirname(fileURLToPath(import.meta.url));
  const probe = readFileSync(join(here, "../assets/fingerprint-probe.html"), "utf8");
  const lit = [...probe.matchAll(/M\('((?:canvas|webgpu|audio|fonts|clientRects)\.[^']*)'/g)].map((m) => m[1]).filter((p) => !p.endsWith("."));
  const webglKeys = ["status", "params.MAX_TEXTURE_SIZE", "precision.VERTEX_FLOAT", "render.fnv", "render.compile", "render.link", "render.glError", "render.pixelBytes", "render.stable", "render.repeats", "render.error", "unmaskedVendor", "unmaskedRenderer", "extensions", "contextAttrs"];
  const webgl = webglKeys.flatMap((k) => ["webgl1." + k, "webgl2." + k]);
  const all = [...new Set([...lit, ...webgl, "clientRects.tm.width"])];
  const uncl = all.filter((p) => classifyPath(p).indexOf("UNCLASSIFIED") === 0);
  if (uncl.length) console.log("   UNCLASSIFIED paths:", uncl.join(", "));
  ok(`contract: all ${all.length} emitted vector paths are target-or-excluded`, uncl.length === 0);
}
// mode-aware: geolocation 'prompt' reads the REAL location → not a spoof target
ok("geo 'prompt' mode: lat/lon NOT a target", !isExpectedTarget("permissioned.geo.latitude", "geolocation", "prompt"));
ok("geo 'manual' mode: lat/lon IS a target", isExpectedTarget("permissioned.geo.latitude", "geolocation", "manual"));

console.log(`\nfp-compare: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
