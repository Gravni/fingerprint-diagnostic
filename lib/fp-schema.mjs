// Typed measurement schema (Codex v4). Pure, dependency-free so it runs in Node
// tests AND the Next server. This is the `schemaStatus` gate: it decides whether
// a session's raw is CURRENT (typed), LEGACY_LOSSY (old flat string map), MIXED
// or INVALID — and enforces that a record never lies about its own type.

export const STATUS_ENUM = [
  "ok", "unsupported", "unavailable-in-context", "permission-required",
  "permission-denied", "blocked", "timeout", "error", "invalid-result",
];
export const VALUETYPE_ENUM = [
  "null", "undefined", "boolean", "string", "number", "bigint", "symbol",
  "function", "array", "object", "arraybuffer", "typedarray", "error",
];
const NUMBER_SPECIAL = ["NaN", "Infinity", "-Infinity", "-0"];

/** Return a list of contract violations for one measurement record ([] = valid). */
export function validateMeasurement(rec) {
  const e = [];
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return ["not-an-object"];
  for (const f of ["path", "context", "phase", "status", "valueType", "value", "error", "meta"])
    if (!(f in rec)) e.push("missing:" + f);
  if (typeof rec.path !== "string" || !rec.path) e.push("path");
  if (typeof rec.context !== "string" || !rec.context) e.push("context");
  if (!STATUS_ENUM.includes(rec.status)) e.push("status-enum:" + rec.status);

  if (rec.status === "error") {
    if (!rec.error || typeof rec.error !== "object" || !rec.error.name) e.push("error-missing");
    if (rec.value !== null) e.push("error-value-not-null"); // errors never live in value
    return e;
  }
  if (rec.status !== "ok") {
    // unsupported / unavailable-in-context / permission-* / blocked / timeout
    if (rec.value !== null) e.push("nonok-value-not-null");
    return e;
  }

  // status === "ok" — valueType must match value exactly (no lying about types)
  const vt = rec.valueType, v = rec.value, sp = rec.meta && rec.meta.special;
  if (!VALUETYPE_ENUM.includes(vt)) e.push("valuetype-enum:" + vt);
  // Lossless-encoder markers (v4.3): an oversized payload rides as {__blobRef},
  // a cycle as {__cycle} — valid substitutes for any container/string valueType.
  const blobbed = v && typeof v === "object" && !Array.isArray(v) && (v.__blobRef || v.__cycle);
  switch (vt) {
    case "boolean": if (typeof v !== "boolean") e.push("boolean-value"); break;
    case "string": if (typeof v !== "string" && !blobbed) e.push("string-value"); break;
    case "number":
      if (sp) { if (!NUMBER_SPECIAL.includes(sp)) e.push("bad-special:" + sp); }
      else if (typeof v !== "number") e.push("number-value");
      break;
    case "array":
      if (v !== null && !Array.isArray(v) && !blobbed) e.push("array-not-array");
      // count is the ORIGINAL length; value may be capped (count > length ⇒ marked, not silent).
      else if (Array.isArray(v) && rec.meta && rec.meta.count != null && rec.meta.count < v.length) e.push("array-count");
      break;
    case "object": if (v === null || typeof v !== "object" || Array.isArray(v)) e.push("object-value"); break;
    case "null": if (v !== null) e.push("null-value"); break;
    case "undefined": if (v !== null) e.push("undefined-value"); break; // undefined ⇒ value null
    case "bigint": if (typeof v !== "string") e.push("bigint-value"); break; // serialized as string
    case "arraybuffer": if (!v || typeof v.byteLength !== "number") e.push("arraybuffer-value"); break;
    case "typedarray": if (!v || typeof v.length !== "number") e.push("typedarray-value"); break;
    case "error": if (!v || !v.name) e.push("error-obj-value"); break;
  }
  return e;
}

/** Schema classification for a whole BROWSER session payload (one jsonl record). */
export function classifySessionSchema(session) {
  const meas = session && session._measurements;
  if (Array.isArray(meas) && meas.length) {
    let bad = 0;
    for (const r of meas) if (validateMeasurement(r).length) bad++;
    if (bad === 0) return "CURRENT";
    return bad < meas.length ? "MIXED" : "INVALID";
  }
  // No typed measurements → the old flat string map: types were lost pre-server.
  return "LEGACY_LOSSY";
}

// A non-ok status (unsupported / blocked / unavailable-in-context / timeout /
// error / invalid-result) is ACCEPTABLE only where it is enumerated here — a
// concrete path pattern + the contexts it applies to (Codex v4.3 #2: allowed
// unsupported/blocked states are listed per probe/path, never accepted
// universally). Anything non-ok that is NOT matched is an UNEXPECTED failure and
// blocks readiness. `error`/`invalid-result` are only ever allowed via an
// explicit entry; policy/coverage statuses (blocked/unsupported/unavailable) are
// allowed only for the enumerated feature families or in the enumerated realms.
const WORKERISH = /worker|worklet/;                     // no document/DOM here
const OPAQUE = /sandboxed-iframe|cross-origin-iframe/;  // opaque origin / cross-site
const ALLOW_NONOK = [
  // Policy-gated / hardware-optional feature families — may be unsupported/blocked/
  // unavailable in ANY context (no GPU, disabled by permissions policy, no device).
  { re: /^webgpu\./, statuses: ["unsupported", "unavailable-in-context", "blocked", "timeout"] },
  { re: /^webrtc\./, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  { re: /^(mediaCaps|mediaDevices)\./, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  { re: /^device\.(battery|gamepads|hasBluetooth|hasUSB|hasHID|hasSerial)/, statuses: ["unsupported", "unavailable-in-context", "invalid-result"] },
  { re: /^keyboard\./, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^storage\./, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^speech\./, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^audio\.realtime/, statuses: ["unsupported", "unavailable-in-context", "error"] },
  { re: /^uach\./, statuses: ["unsupported", "unavailable-in-context"] },        // non-Chromium
  { re: /^codecs\./, statuses: ["unavailable-in-context"] },                     // no media element in workers
  { re: /^intlx\.|^wasm\.|^cssSupports/, statuses: ["unsupported"] },
  // Document-dependent probes are legitimately unavailable in workers/worklets.
  { re: /^(canvas|webgl|fonts|clientRects|css|rects)\b|\./, ctx: WORKERISH, statuses: ["unavailable-in-context", "unsupported"] },
  // permissioned phase: the user may deny / not answer.
  { re: /^permissioned\./, statuses: ["permission-denied", "permission-required", "timeout", "unavailable-in-context", "blocked"] },
  // control engines run in main-frame only.
  { re: /^control\./, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  // in an opaque / cross-site realm, a probe may be blocked/denied by the sandbox
  // — SecurityError (→blocked) OR a plain "not supported in this context" TypeError
  // (recorded as `error`). Both are EXPECTED coverage there, never a bug (Codex
  // v4.3 #2: expected sandbox/cross-origin denials). Main + same-origin frames
  // stay strict (no `error` leniency).
  { re: /./, ctx: OPAQUE, statuses: ["blocked", "unavailable-in-context", "error"] },
];
/** Is a non-ok status acceptable for this {path,context}? (Codex v4.3 #2) */
export function nonOkAllowed(path, context, status) {
  if (status === "ok") return true;
  for (const a of ALLOW_NONOK) {
    if (a.ctx && !a.ctx.test(context || "")) continue;
    if (a.re.test(path || "") && a.statuses.indexOf(status) >= 0) return true;
  }
  return false;
}
/** Scan one context payload for UNEXPECTED non-ok records (Codex v4.3 #2). */
export function scanUnexpected(session, context) {
  const meas = session && session._measurements;
  if (!Array.isArray(meas)) return [];
  const out = [];
  for (const r of meas) {
    if (r && r.status && r.status !== "ok" && !nonOkAllowed(r.path, context, r.status))
      out.push({ path: r.path, status: r.status });
  }
  return out;
}

// Duplicate {context,path}: within ONE context a path must appear at most once.
// Two records for the same path silently overwrite in any path-keyed map, so a
// signal vanishes with no trace (Codex v4.2 #7 — uach.brands/uach.mobile were
// emitted twice per realm). Returns [{path,count}] for offenders; [] if clean.
export function findDuplicatePaths(session) {
  const meas = session && session._measurements;
  if (!Array.isArray(meas)) return [];
  const counts = new Map();
  for (const r of meas) { const p = r && r.path; if (typeof p === "string") counts.set(p, (counts.get(p) || 0) + 1); }
  const dups = [];
  for (const [p, c] of counts) if (c > 1) dups.push({ path: p, count: c });
  return dups.sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
}

// The NETWORK record is a flat capture object (JA4/TLS/HTTP), NOT the typed
// browser envelope — so it needs its OWN schema check. Running the browser
// classifier on it returns LEGACY_LOSSY and would wrongly drag a fully-typed
// browser session down (Codex v4.2 #3). CURRENT when the net-v4 fields are all
// present; PARTIAL if some; MISSING if none / not an object.
export const NET_REQUIRED = ["ja4", "tlsVersion", "httpVersion", "headerOrder", "parserVersion", "captureBuild"];
export function classifyNetworkSchema(meas) {
  if (!meas || typeof meas !== "object" || Array.isArray(meas)) return "MISSING";
  // net-v5: strict VERSIONED schema with typed arrays/objects (Codex v4.3 #8).
  if (meas.netSchemaVersion === "net-v5") {
    const t = meas.tlsTyped;
    const typedOk = t && Array.isArray(t.ciphers) && Array.isArray(t.extensions) && Array.isArray(t.sigAlgs)
      && Array.isArray(t.curves) && Array.isArray(t.pointFormats) && Array.isArray(meas.httpHeadersTyped);
    const flatOk = meas.ja4 && meas.tlsVersion && meas.httpVersion && meas.parserVersion && meas.captureBuild;
    if (typedOk && flatOk) return "CURRENT";
    return (typedOk || flatOk) ? "PARTIAL" : "MISSING";
  }
  // net-v4 legacy flat record (kept for the diagnostic regression fixture).
  let present = 0;
  for (const k of NET_REQUIRED) if (meas[k] != null && meas[k] !== "") present++;
  return present === NET_REQUIRED.length ? "CURRENT" : present > 0 ? "PARTIAL" : "MISSING";
}
