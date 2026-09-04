// Per-vector EXPECTATION registry (Codex v4.2 #16 / v4.3 #6) — the single,
// importable source (TS server via fp-vectors AND the unit test). Built from the
// ACTUAL paths the collector emits. Every spoofable-vector path is either a
// TARGET (expected to change when that vector is spoofed → can be leaked/masked)
// or an explicit metadata EXCLUSION (never a masking claim). A contract test
// asserts every emitted vector path is one or the other — no path falls through.

// Map a measurement path to the anti-detect vector it belongs to (single source;
// lib/fingerprint.ts delegates here so server + test agree).
export function vectorForPath(path) {
  const head = String(path || "").split(".")[0];
  switch (head) {
    case "canvas": return "canvas";
    case "webgl": case "webgl1": case "webgl2": return "webgl";
    case "audio": return "audio";
    case "fonts": return "fonts";
    case "webgpu": return "webgpu";
    case "mediaDevices": return "mediaDevices";
    case "clientRects": return "clientRects";
    case "permissioned": return /(^|\.)geo\./i.test(path) ? "geolocation" : null;
    case "locale": return /(resolvedTZ|tzOffset|dtfWinter|dtfSummer|dateToLocale|(^|\.)tz$)/i.test(path) ? "timezone" : null;
    default: return /(^|\.)(timezone|timeZone|tzOffset)$/i.test(path) ? "timezone" : null;
  }
}

// TARGETS — the fields a spoofed vector is EXPECTED to change (from the real
// collector paths: canvas.pixelFnv/pixelSha256/repeats, WebGL render digests/
// repeats + unmasked*, WebGPU render/compute digests + adapter identity, …).
export const EXPECT_TARGETS = {
  canvas:       /(^|\.)(pixelFnv|pixelSha256|repeats)$/i,
  webgl:        /(?:^|\.)(?:unmaskedRenderer|unmaskedVendor)$|\.render\.(?:fnv|sha256|repeats|fnvRepeats|sha256Repeats)$/i,
  clientRects:  /(^|\.)(bcr|rangeRects|svgBBox|svgTextLen)$|(^|\.)tm\./i,
  audio:        /^audio\.offline\.(?:sum|sha256|fnv|sha256Repeats)$/i,
  webgpu:       /^webgpu\.(?:vendor|architecture|device|description|features|(?:compute|render)\.(?:hash|sha256))$|^webgpu\.limits\./i,
  mediaDevices: /^mediaDevices\.(audioinput|audiooutput|videoinput|total|groups)$/i,
  fonts:        /^fonts\.(hash|count|list)$/i,
  timezone:     /resolvedTZ|tzOffset|dtfWinter|dtfSummer|dateToLocale|(^|\.)tz$/i,
  geolocation:  /^permissioned\.geo\.(latitude|longitude|coarseBucket)$/i,
};
// EXCLUSIONS — metadata / capability / volatile fields that are NOT masking
// targets even when the vector is spoofed (a difference here is just `different`).
export const EXCLUDE_META = {
  canvas:       /^canvas\.(width|height|winding|status|available|encFmt|encLen|pixelBytes|stable|error)$/i,
  webgl:        /\.(?:status|extensions|contextAttrs)$|\.params\.|\.precision\.|\.render\.(?:compile|link|glError|width|height|pixelBytes|stable)$/i,
  clientRects:  /^clientRects\.(status|error|rangeRectCount)$/i,
  audio:        /^audio\.(?:available|status)$|^audio\.offline\.(?:sampleCount|byteLength|sampleRate|stable)$|^audio\.realtime\.(?:available|status|baseLatency|outputLatency|sampleRate|state)$/i,
  webgpu:       /^webgpu\.(?:status|available|isFallback|preferredFormat|wgslFeatures)$|^webgpu\.(?:compute|render)\.(?:status|hashAlgorithm|byteLength|valueCount|pixelBytes|width|height|bytesPerRow|compilationMessages|compilationErrors|deviceLost)$/i,
  mediaDevices: /^mediaDevices\.(available|supportedConstraints|error)$/i,
  fonts:        /^fonts\.(available|error)$/i,
  timezone:     /^$/,   // all timezone paths are targets
  geolocation:  /^permissioned\.geo\.(accuracy|altitude|altitudeAccuracy|heading|speed|timestamp)$|^permissioned\.geo$/i,
};

/** Is this path one the given spoofed vector is EXPECTED to change? Mode-aware:
 *  geolocation `prompt` mode reads the REAL location, so it isn't a spoof target. */
export function isExpectedTarget(path, vector, mode) {
  const passThrough = {
    canvas: "direct", webgl: "direct", clientRects: "direct", audio: "direct",
    webgpu: "direct", mediaDevices: "direct", fonts: "real",
    timezone: "off", geolocation: "off",
  };
  if (mode && (mode === passThrough[vector] || (vector === "geolocation" && mode === "prompt"))) return false;
  // The product's WebGL `noise` mode promises a different rendering result. It
  // does not promise to rewrite the GPU identity strings; treating an unchanged
  // vendor as a leak would be a false sales claim.
  if (vector === "webgl" && mode === "noise" && /unmasked(?:Vendor|Renderer)/i.test(path)) return false;
  const re = EXPECT_TARGETS[vector];
  return !!re && re.test(path);
}
/** Classify a path for the contract test: target | excluded | not-a-vector |
 *  UNCLASSIFIED (a spoofable-vector path with neither a target rule nor an
 *  exclusion — the test fails on this so the path must be classified). */
export function classifyPath(path) {
  const v = vectorForPath(path);
  if (!v) return "not-a-vector";
  if (EXPECT_TARGETS[v] && EXPECT_TARGETS[v].test(path)) return "target";
  if (EXCLUDE_META[v] && EXCLUDE_META[v].test(path)) return "excluded";
  return "UNCLASSIFIED:" + v;
}
