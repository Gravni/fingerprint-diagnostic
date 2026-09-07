// Typed measurement schema (Codex v4). It runs in Node tests and the Next server
// and shares the dependency-free SHA implementation with the browser encoder.
// This is the `schemaStatus` gate: it decides whether
// a session's raw is CURRENT (typed), LEGACY_LOSSY (old flat string map), MIXED
// or INVALID — and enforces that a record never lies about its own type.

import { sha256hex } from "./fp-encode.mjs";
import { isBlobLocatorForAddress } from "./fp-blob.mjs";
import { md5hex } from "./md5.mjs";
import { isIP } from "node:net";

export const STATUS_ENUM = [
  "ok", "unsupported", "unavailable-in-context", "permission-required",
  "permission-denied", "blocked", "timeout", "error", "invalid-result",
];
export const VALUETYPE_ENUM = [
  "null", "undefined", "boolean", "string", "number", "bigint", "symbol",
  "function", "array", "object", "arraybuffer", "typedarray", "error",
];
const NUMBER_SPECIAL = ["NaN", "Infinity", "-Infinity", "-0"];
// Keep the validator's accepted inline envelope aligned with fp-encode.mjs.
// These budgets are shared across the whole encoded value, not reset for each
// branch, so a broad tree cannot turn individually small children into an
// unbounded validation job.
const ENCODED_MAX_DEPTH = 8;
const ENCODED_MAX_NODES = 10000;
const ENCODED_MAX_KEYS = 512;
const ENCODED_MAX_ARRAY_LENGTH = 8192;

function encodedLimit(state, kind) {
  if (!state.limit) state.limit = `encoded-limit:${kind}`;
  return [state.limit];
}

function validateEncodedValue(vt, v, meta = {}, depth = 0, state = { nodes: 0, limit: null }) {
  if (state.limit) return [state.limit];
  state.nodes++;
  if (state.nodes > ENCODED_MAX_NODES) return encodedLimit(state, "nodes");
  if (depth > ENCODED_MAX_DEPTH) return encodedLimit(state, "depth");
  const e = [];
  if (!VALUETYPE_ENUM.includes(vt)) return ["valuetype-enum:" + vt];
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return ["encoded-meta"];
  const sp = meta.special, count = meta.count;
  if (sp != null && vt !== "number") e.push("special-nonnumber");
  if (count != null && vt !== "array") e.push("count-nonarray");

  const isObject = v && typeof v === "object" && !Array.isArray(v);
  const hasBlob = !!(isObject && Object.prototype.hasOwnProperty.call(v, "__blobRef"));
  const hasCycle = !!(isObject && Object.prototype.hasOwnProperty.call(v, "__cycle"));
  let blobbed = false, cycled = false;
  if (hasBlob) {
    const b = v.__blobRef;
    blobbed = !!(b && typeof b === "object" && !Array.isArray(b)
      && typeof b.kind === "string" && b.kind.length > 0
      && Number.isInteger(b.length) && b.length >= 0
      && typeof b.sha256 === "string" && /^[0-9a-f]{64}$/.test(b.sha256)
      && typeof b.fnv === "string" && /^[0-9a-f]{8}$/.test(b.fnv)
      && (b.preview === null || typeof b.preview === "string"));
    if (!blobbed) e.push("blobref");
    else {
      if (b.kind !== vt) e.push("blobref-kind");
      // `complete:false` hashes only a deterministic truncation marker, not the
      // omitted observation. It is useful diagnostic evidence, but it cannot
      // satisfy a one-shot CURRENT/READY capture or support an equality claim.
      // Current records must state the complete contract explicitly; accepting
      // an older short `{sha256,length}` shape would let a missing completeness
      // flag masquerade as content-addressed evidence.
      const modernContract = b.complete === true && b.hashScope === "content"
        && b.addressVersion === "fp-blob-address-v1"
        && typeof b.addressSha256 === "string" && /^[0-9a-f]{64}$/.test(b.addressSha256)
        && typeof b.addressFnv === "string" && /^[0-9a-f]{8}$/.test(b.addressFnv)
        && typeof b.encoding === "string" && b.encoding.length > 0
        && typeof b.reason === "string" && b.reason.length > 0
        && typeof b.lengthUnit === "string" && b.lengthUnit.length > 0
        && typeof b.stored === "boolean";
      if (!modernContract) e.push("blobref-incomplete");
      if (b.complete === true && b.hashScope === "content"
          && !isBlobLocatorForAddress(b.locator, b.addressSha256)) e.push("blobref-locator");
      if (b.sinkError !== undefined) e.push("blobref-sink-error");
    }
  }
  if (hasCycle) {
    cycled = v.__cycle === true && Object.keys(v).length === 1;
    if (!cycled) e.push("cycle-marker");
    else if (vt !== "array" && vt !== "object") e.push("cycle-marker-kind");
  }
  const marked = blobbed || cycled;

  switch (vt) {
    case "boolean": if (typeof v !== "boolean") e.push("boolean-value"); break;
    case "string": if (typeof v !== "string" && !blobbed) e.push("string-value"); break;
    case "number":
      if (sp != null) {
        if (!NUMBER_SPECIAL.includes(sp)) e.push("bad-special:" + sp);
        else if (sp === "-0" ? v !== 0 : v !== null) e.push("special-value");
      } else if (typeof v !== "number") e.push("number-value");
      else if (!Number.isFinite(v)) e.push("nonfinite-number");
      else if (Object.is(v, -0)) e.push("unmarked-negative-zero");
      break;
    case "array":
      if (count != null && (!Number.isInteger(count) || count < 0)) e.push("array-count");
      if (!Array.isArray(v) && !marked) e.push("array-not-array");
      else if (Array.isArray(v)) {
        if (v.length > ENCODED_MAX_ARRAY_LENGTH) return encodedLimit(state, "array-length");
        if (depth >= ENCODED_MAX_DEPTH) return encodedLimit(state, "depth");
        if (count != null && count < v.length) e.push("array-count");
        for (let i = 0; i < v.length; i++) {
          const child = v[i];
          if (!child || typeof child !== "object" || Array.isArray(child) || !("valueType" in child) || !("value" in child)) {
            e.push(`nested:${i}:shape`);
            continue;
          }
          for (const err of validateEncodedValue(child.valueType, child.value, { special: child.special, count: child.count }, depth + 1, state))
            e.push(`nested:${i}:${err}`);
          if (state.limit) return [state.limit];
        }
      }
      break;
    case "object":
      if (!isObject) e.push("object-value");
      else if (!marked) {
        const props = v.props;
        const depthMarker = v.__maxDepth === true;
        if (typeof v.__ctor !== "string" || (!depthMarker && (!props || typeof props !== "object" || Array.isArray(props)))) {
          e.push("object-shape");
        } else if (!depthMarker) {
          const keys = Object.keys(props);
          if (keys.length > ENCODED_MAX_KEYS) return encodedLimit(state, "keys");
          if (depth >= ENCODED_MAX_DEPTH) return encodedLimit(state, "depth");
          for (const k of keys) {
            const child = props[k];
            if (!child || typeof child !== "object" || Array.isArray(child) || !("valueType" in child) || !("value" in child)) {
              e.push(`nested:${k}:shape`);
              continue;
            }
            for (const err of validateEncodedValue(child.valueType, child.value, { special: child.special, count: child.count }, depth + 1, state))
              e.push(`nested:${k}:${err}`);
            if (state.limit) return [state.limit];
          }
        }
      }
      break;
    case "null": if (v !== null) e.push("null-value"); break;
    case "undefined": if (v !== null) e.push("undefined-value"); break;
    case "bigint": if (typeof v !== "string" || !/^-?\d+$/.test(v)) e.push("bigint-value"); break;
    case "symbol": if (typeof v !== "string") e.push("symbol-value"); break;
    case "function": if (typeof v !== "string") e.push("function-value"); break;
    case "arraybuffer":
      if (!isObject || !Number.isInteger(v.byteLength) || v.byteLength < 0
          || typeof v.contentHash !== "string" || !/^[0-9a-f]{8}$/.test(v.contentHash)
          || typeof v.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(v.sha256)) e.push("arraybuffer-value");
      break;
    case "typedarray":
      if (!isObject || typeof v.ctor !== "string" || !Number.isInteger(v.length) || v.length < 0
          || !Number.isInteger(v.byteLength) || v.byteLength < 0
          || typeof v.contentHash !== "string" || !/^[0-9a-f]{8}$/.test(v.contentHash)
          || typeof v.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(v.sha256)) e.push("typedarray-value");
      break;
    case "error":
      if (!isObject || typeof v.name !== "string" || !v.name || typeof v.message !== "string") e.push("error-obj-value");
      break;
  }
  return e;
}

function validateMeasurementWithState(rec, encodedState) {
  const e = [];
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return ["not-an-object"];
  for (const f of ["path", "context", "phase", "status", "valueType", "value", "error", "meta"])
    if (!(f in rec)) e.push("missing:" + f);
  if (typeof rec.path !== "string" || !rec.path) e.push("path");
  if (typeof rec.context !== "string" || !rec.context) e.push("context");
  if (typeof rec.phase !== "string" || !rec.phase) e.push("phase");
  if (!rec.meta || typeof rec.meta !== "object" || Array.isArray(rec.meta)) e.push("meta");
  if (!STATUS_ENUM.includes(rec.status)) e.push("status-enum:" + rec.status);

  if (rec.status === "error") {
    if (!rec.error || typeof rec.error !== "object" || Array.isArray(rec.error) || typeof rec.error.name !== "string" || !rec.error.name) e.push("error-missing");
    if (rec.value !== null) e.push("error-value-not-null"); // errors never live in value
    if (rec.valueType !== null && rec.valueType !== "null") e.push("nonvalue-valuetype");
    return e;
  }
  if (rec.status !== "ok") {
    // unsupported / unavailable-in-context / permission-* / blocked / timeout
    if (rec.value !== null) e.push("nonok-value-not-null");
    if (rec.valueType !== null && rec.valueType !== "null") e.push("nonvalue-valuetype");
    return e;
  }

  // status === "ok" — valueType must match value exactly (no lying about types)
  if (rec.error !== null) e.push("unexpected-error");
  e.push(...validateEncodedValue(rec.valueType, rec.value, rec.meta, 0, encodedState));
  return e;
}

/** Return a list of contract violations for one measurement record ([] = valid). */
export function validateMeasurement(rec) {
  return validateMeasurementWithState(rec, { nodes: 0, limit: null });
}

/** Schema classification for a whole BROWSER session payload (one jsonl record). */
export function classifySessionSchema(session) {
  const meas = session && session._measurements;
  if (Array.isArray(meas)) {
    if (meas.length === 0) return "INVALID";
    if (meas.length > ENCODED_MAX_ARRAY_LENGTH) return "INVALID";
    let bad = 0;
    const encodedState = { nodes: 0, limit: null };
    for (const r of meas) {
      if (validateMeasurementWithState(r, encodedState).length) bad++;
      if (encodedState.limit) return "INVALID";
    }
    if (bad === 0) {
      // Typed rows alone do not identify the producer contract. In particular,
      // v4.3 emitted `_schema=typed-v4-partial` but the old classifier silently
      // promoted it to CURRENT. Only the exact reviewed schema marker can pass.
      if (session._schema === "typed-v4") return "CURRENT";
      if (session._schema == null || session._schema === "typed-v4-partial") return "MIXED";
      return "INVALID";
    }
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
const WORKERISH = /^(?:dedicated-worker(?:-module)?|shared-worker(?:-module)?|service-worker|audio-worklet)$/;
const AUDIO_WORKLET = /^audio-worklet$/;
const ALLOW_NONOK = [
  // Optional capability *status* fields. A failure in a result leaf/hash is not
  // covered by the same row and therefore blocks readiness.
  { re: /^webgpu\.(?:available|status)$/, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  // These seven WebGPU properties are optional or have changed across Chromium
  // revisions. The collector emits an explicit absence for exactly these
  // metadata leaves; compute/render evidence remains strict.
  { re: /^webgpu\.(?:isFallback|vendor|architecture|device|description|wgslFeatures|preferredFormat)$/, statuses: ["unavailable-in-context"] },
  { re: /^webrtc\.status$/, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  { re: /^mediaDevices\.available$/, statuses: ["unsupported", "unavailable-in-context", "blocked"] },
  { re: /^mediaCaps\.(?:mediaCapabilities|webcodecs|eme)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^device\.(battery|gamepads)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^keyboard\.available$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^storage\.(?:estimate|usageDetails|persisted)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^speech\.available$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^audio\.available$/, statuses: ["unsupported", "unavailable-in-context"] },
  // Worker globals can expose OfflineAudioContext without exposing the realtime
  // AudioContext constructor. Only the availability marker is optional there;
  // a failed realtime measurement or absent window implementation still fails.
  { re: /^audio\.realtime\.available$/, ctx: WORKERISH, statuses: ["unavailable-in-context"] },
  { re: /^uach\.available$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^intlx\.(?:status|tzCount|calendars|currencyCount|displayRegion|displayLang|segmenter)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^wasm\.status$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^cssSupports\.available$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^misc\.(?:perfMemory|notifPermission|pluginsLen|mimeTypesLen)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^misc\.perm\.[^.]+$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^hooks\.(?:native|navDesc)\./, statuses: ["unavailable-in-context"] },
  { re: /^webgl\.(?:webgl|webgl2)\.(?:status|unmaskedVendor|unmaskedRenderer)$/, statuses: ["unsupported", "unavailable-in-context"] },
  { re: /^codecs\.(?:canPlay|mse)\[/, ctx: WORKERISH, statuses: ["unavailable-in-context"] },
  { re: /^env\.(?:vvScale|vvWidth)$/, statuses: ["unavailable-in-context"] },
  // Document-dependent probes are legitimately unavailable in workers/worklets.
  { re: /^(?:canvas\.status|fonts\.available|clientRects\.status|css\.available)$/, ctx: WORKERISH, statuses: ["unavailable-in-context", "unsupported"] },
  // `sandbox="allow-scripts"` deliberately creates an opaque origin. Chromium
  // denies origin-bound Storage/Cache access and selected navigator capabilities
  // there. Enumerate only the proven denials; other blocked paths still fail.
  { re: /^storage\.(?:localStorage|sessionStorage|caches|estimate)$/, ctx: /^sandboxed-iframe$/, statuses: ["blocked"] },
  { re: /^keyboard\.available$/, ctx: /^sandboxed-iframe$/, statuses: ["blocked"] },
  { re: /^navigator\.serviceWorker$/, ctx: /^sandboxed-iframe$/, statuses: ["blocked"] },
  // AudioWorkletGlobalScope intentionally has no Navigator. These exact fields
  // come from the trimmed worklet adapter; ordinary workers must provide them.
  { re: /^(?:navigator\.(?:userAgent|platform|hardwareConcurrency|deviceMemory)|worklet\.hasNavigator|locale\.(?:tz|locale))$/, ctx: AUDIO_WORKLET, statuses: ["unavailable-in-context"] },
  // The permissioned phase is mandatory for the one-shot employee capture.
  // Denial, an unanswered prompt or timeout are valid observations, but they are
  // not acceptable for READY. Only a genuinely absent API/device is tolerated.
  { re: /^permissioned\.(?:getUserMedia|geo)(?:\.|$)/, ctx: /^permissioned$/, statuses: ["unavailable-in-context"] },
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
    if (!r || typeof r !== "object") continue;
    if (context && r.context !== context) {
      out.push({ path: r.path, status: "context-mismatch", recordContext: r.context });
      continue;
    }
    if (r.status && r.status !== "ok" && !nonOkAllowed(r.path, r.context || context, r.status))
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
  for (const r of meas) {
    const p = r && r.path, c = r && r.context;
    if (typeof p === "string" && typeof c === "string") {
      const k = c + "\u0000" + p;
      const cur = counts.get(k) || { context: c, path: p, count: 0 };
      cur.count++;
      counts.set(k, cur);
    }
  }
  const dups = [];
  for (const v of counts.values()) if (v.count > 1) dups.push(v);
  return dups.sort((a, b) => b.count - a.count || a.context.localeCompare(b.context) || a.path.localeCompare(b.path));
}

// The NETWORK record is a flat capture object (JA4/TLS/HTTP), NOT the typed
// browser envelope — so it needs its OWN schema check. Running the browser
// classifier on it returns LEGACY_LOSSY and would wrongly drag a fully-typed
// browser session down (Codex v4.2 #3). Only the current, typed, explicitly
// versioned schema can be CURRENT. A complete old flat record is LEGACY; an
// incomplete current record is PARTIAL; malformed typed data is INVALID.
export const NET_REQUIRED = ["ja4", "tlsVersion", "httpVersion", "headerOrder", "parserVersion", "captureBuild"];
export function classifyNetworkSchema(meas) {
  if (!meas || typeof meas !== "object" || Array.isArray(meas)) return "MISSING";
  const version = meas.netSchemaVersion;
  if (version === "net-v5" || version === "net-v6") {
    const isV6 = version === "net-v6";
    const t = meas.tlsTyped;
    const u32 = (v) => Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
    const u16 = (v) => Number.isInteger(v) && v >= 0 && v <= 0xffff;
    const u8 = (v) => Number.isInteger(v) && v >= 0 && v <= 0xff;
    const validVector = (v, check) => Array.isArray(v) && v.every(check);
    const validAlpnRaw = (v) => Array.isArray(v) && v.every((token) => validVector(token, u8));
    const validHeader = (h, i) => h && typeof h === "object" && !Array.isArray(h)
      && typeof h.name === "string" && h.name.length > 0 && typeof h.value === "string"
      && (!isV6 || h.wireIndex === i);
    const validHeaders = (v) => Array.isArray(v) && v.every(validHeader);
    const grease = (n) => (n & 0x0f0f) === 0x0a0a && (n >> 8) === (n & 0xff);
    const hex4 = (n) => n.toString(16).padStart(4, "0");
    const cap99 = (n) => String(Math.min(99, n)).padStart(2, "0");
    const tlsVersionCodes = {
      0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
      0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
    };
    const alpnCode = (raw) => {
      if (!Array.isArray(raw) || raw.length === 0) return "00";
      const first = raw[0], last = raw[raw.length - 1];
      const alnum = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
      if (alnum(first) && alnum(last)) return String.fromCharCode(first) + String.fromCharCode(last);
      const hex = raw.map((x) => x.toString(16).padStart(2, "0")).join("");
      return hex ? hex[0] + hex[hex.length - 1] : "00";
    };

    // Distinguish absent fields (PARTIAL capture) from present malformed fields
    // (INVALID capture). Downstream comparison must never consume fake "typed"
    // vectors such as ["4865"] or reordered wire indexes.
    if (t != null && (typeof t !== "object" || Array.isArray(t))) return "INVALID";
    if (t) {
      for (const k of ["ciphers", "extensions", "sigAlgs", "curves"])
        if (k in t && !validVector(t[k], u16)) return "INVALID";
      if ("pointFormats" in t && !validVector(t.pointFormats, u8)) return "INVALID";
      if ("alpnOffered" in t && (!Array.isArray(t.alpnOffered) || !t.alpnOffered.every((x) => typeof x === "string"))) return "INVALID";
      if ("alpnRaw" in t && !validAlpnRaw(t.alpnRaw)) return "INVALID";
    }
    if (meas.httpHeadersTyped != null && !validHeaders(meas.httpHeadersTyped)) return "INVALID";

    let expectedTlsVersion = null;
    if (isV6 && t) {
      if (!u16(t.tlsRecordVersion)
          || !Object.prototype.hasOwnProperty.call(t, "supportedVersionMax")
          || !(t.supportedVersionMax === null || u16(t.supportedVersionMax))) return "INVALID";
      if (!u16(t.handshakeVersion)) return "INVALID";
      if (["ciphers", "extensions", "sigAlgs", "curves", "pointFormats"].some((k) => !Array.isArray(t[k]) || t[k].length === 0)) return "INVALID";
      const offeredFromRaw = (t.alpnRaw || []).map((bytes) => String.fromCharCode(...bytes));
      if (!Array.isArray(t.alpnOffered) || offeredFromRaw.join("\u0000") !== t.alpnOffered.join("\u0000")) return "INVALID";
      expectedTlsVersion = tlsVersionCodes[t.supportedVersionMax ?? t.tlsRecordVersion] || "00";
      if (meas.tlsVersion !== expectedTlsVersion) return "INVALID";
    }

    const typedOk = t && validVector(t.ciphers, u16) && validVector(t.extensions, u16)
      && validVector(t.sigAlgs, u16) && validVector(t.curves, u16)
      && validVector(t.pointFormats, u8)
      && (!isV6 || (Array.isArray(t.alpnOffered) && validAlpnRaw(t.alpnRaw)))
      && validHeaders(meas.httpHeadersTyped);
    const flatOk = NET_REQUIRED.every((k) => typeof meas[k] === "string" && meas[k].length > 0);

    // v5 lacked the wire-level H2 evidence required by the current contract.
    // A structurally complete v5 capture remains useful as LEGACY evidence.
    if (!isV6) return typedOk && flatOk ? "LEGACY" : "PARTIAL";

    const v6FlatPresent = ["ja3", "ja3String", "sni"].every((k) => typeof meas[k] === "string" && meas[k].length > 0);
    if (("ja4" in meas && !/^[tq][0-9]{2}[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/.test(meas.ja4))
        || ("ja3" in meas && !/^[0-9a-f]{32}$/.test(meas.ja3))
        || ("ja3String" in meas && !/^\d+,[0-9-]*,[0-9-]*,[0-9-]*,[0-9-]*$/.test(meas.ja3String))) return "INVALID";
    if (t && typeof meas.ja4 === "string" && v6FlatPresent) {
      const ciphers = t.ciphers.filter((x) => !grease(x));
      const extensions = t.extensions.filter((x) => !grease(x));
      const cipherText = ciphers.map(hex4).sort().join(",");
      const extText = extensions.filter((x) => x !== 0 && x !== 16).map(hex4).sort().join(",");
      const sigText = t.sigAlgs.filter((x) => !grease(x)).map(hex4).join(",");
      const expectedJa4 = `t${expectedTlsVersion}${meas.sni === "none" ? "i" : "d"}${cap99(ciphers.length)}${cap99(extensions.length)}${alpnCode(t.alpnRaw[0])}`
        + `_${cipherText ? sha256hex(cipherText).slice(0, 12) : "000000000000"}`
        + `_${extText ? sha256hex(sigText ? `${extText}_${sigText}` : extText).slice(0, 12) : "000000000000"}`;
      if (meas.ja4 !== expectedJa4) return "INVALID";
      const canonicalJa3 = [
        t.handshakeVersion,
        ciphers.join("-"),
        extensions.join("-"),
        t.curves.filter((x) => !grease(x)).join("-"),
        t.pointFormats.join("-"),
      ].join(",");
      if (meas.ja3String !== canonicalJa3 || meas.ja3 !== md5hex(canonicalJa3)) return "INVALID";
    }

    const h2 = meas.http2;
    const settingNames = { 1: "headerTableSize", 2: "enablePush", 3: "maxConcurrentStreams", 4: "initialWindowSize", 5: "maxFrameSize", 6: "maxHeaderListSize", 8: "enableConnectProtocol" };
    if (h2 != null && (typeof h2 !== "object" || Array.isArray(h2))) return "INVALID";
    if (h2) {
      if ("settings" in h2) {
        if (!Array.isArray(h2.settings)) return "INVALID";
        for (let i = 0; i < h2.settings.length; i++) {
          const s = h2.settings[i];
          if (!s || typeof s !== "object" || Array.isArray(s)
              || !u16(s.id) || !u32(s.value) || s.wireIndex !== i
              || !(s.name === null || typeof s.name === "string")) return "INVALID";
          const expectedName = settingNames[s.id] || null;
          if (s.name !== expectedName) return "INVALID";
          if ((s.id === 2 || s.id === 8) && s.value !== 0 && s.value !== 1) return "INVALID";
          if (s.id === 4 && s.value > 0x7fffffff) return "INVALID";
          if (s.id === 5 && (s.value < 16384 || s.value > 16777215)) return "INVALID";
        }
      }
      if ("settingsOrder" in h2) {
        if (!validVector(h2.settingsOrder, u16)) return "INVALID";
        if (Array.isArray(h2.settings)
            && h2.settingsOrder.join(",") !== h2.settings.map((s) => s.id).join(",")) return "INVALID";
      }
      if ("settingsEffective" in h2) {
        if (!h2.settingsEffective || typeof h2.settingsEffective !== "object" || Array.isArray(h2.settingsEffective)
            || !Object.values(h2.settingsEffective).every(u32)) return "INVALID";
        if (Array.isArray(h2.settings)) {
          const expectedEffective = {};
          for (const s of h2.settings) expectedEffective[s.name || `unknown_${s.id}`] = s.value;
          if (JSON.stringify(Object.entries(h2.settingsEffective).sort())
              !== JSON.stringify(Object.entries(expectedEffective).sort())) return "INVALID";
        }
      }
      if ("settingsPayloadSha256" in h2 && (typeof h2.settingsPayloadSha256 !== "string"
          || !/^[0-9a-f]{64}$/.test(h2.settingsPayloadSha256))) return "INVALID";
      if ("settingsPayloadHex" in h2 && (typeof h2.settingsPayloadHex !== "string"
          || !/^(?:[0-9a-f]{12})+$/.test(h2.settingsPayloadHex))) return "INVALID";
      if (Array.isArray(h2.settings) && typeof h2.settingsPayloadHex === "string") {
        const decodedHex = h2.settings.map((s) => hex4(s.id) + s.value.toString(16).padStart(8, "0")).join("");
        if (decodedHex !== h2.settingsPayloadHex) return "INVALID";
        const bytes = [];
        for (let i = 0; i < h2.settingsPayloadHex.length; i += 2) bytes.push(parseInt(h2.settingsPayloadHex.slice(i, i + 2), 16));
        if (h2.settingsPayloadSha256 !== sha256hex(bytes)) return "INVALID";
      }
      if ("pseudoHeaderOrder" in h2) {
        if (!Array.isArray(h2.pseudoHeaderOrder)
            || !h2.pseudoHeaderOrder.every((x) => typeof x === "string" && /^:[a-z]+$/.test(x))
            || new Set(h2.pseudoHeaderOrder).size !== h2.pseudoHeaderOrder.length) return "INVALID";
        if (Array.isArray(meas.httpHeadersTyped)) {
          const observed = meas.httpHeadersTyped.filter((x) => x.name.startsWith(":")).map((x) => x.name);
          if (observed.join(",") !== h2.pseudoHeaderOrder.join(",")) return "INVALID";
        }
      }
      if ("errors" in h2 && (!Array.isArray(h2.errors) || !h2.errors.every((x) => typeof x === "string"))) return "INVALID";
    }
    if (Array.isArray(meas.httpHeadersTyped)
        && typeof meas.headerOrder === "string"
        && meas.headerOrder !== meas.httpHeadersTyped.map((x) => x.name).join(",")) return "INVALID";
    if (Array.isArray(meas.httpHeadersTyped)) {
      const names = meas.httpHeadersTyped.map((x) => x.name);
      const requiredPseudo = [":method", ":authority", ":scheme", ":path"];
      if (!requiredPseudo.every((name) => names.includes(name)) || !names.includes("user-agent")) return "INVALID";
      const firstRegular = names.findIndex((name) => !name.startsWith(":"));
      if (firstRegular >= 0 && names.slice(firstRegular).some((name) => name.startsWith(":"))) return "INVALID";
    }
    const uaFields = [
      ["userAgent", "user-agent"],
      ["secChUa", "sec-ch-ua"],
      ["secChUaMobile", "sec-ch-ua-mobile"],
      ["secChUaPlatform", "sec-ch-ua-platform"],
      ["secChUaPlatformVersion", "sec-ch-ua-platform-version"],
      ["secChUaArch", "sec-ch-ua-arch"],
      ["secChUaBitness", "sec-ch-ua-bitness"],
      ["secChUaModel", "sec-ch-ua-model"],
      ["secChUaFullVersionList", "sec-ch-ua-full-version-list"],
      ["secChUaWow64", "sec-ch-ua-wow64"],
      ["secChUaFormFactors", "sec-ch-ua-form-factors"],
    ];
    let uaFieldsPresent = true;
    if (Array.isArray(meas.httpHeadersTyped)) {
      const valuesByName = new Map();
      for (const header of meas.httpHeadersTyped) {
        const name = header.name.toLowerCase();
        const values = valuesByName.get(name) || [];
        values.push(header.value);
        valuesByName.set(name, values);
      }
      for (const [field, headerName] of uaFields) {
        if (typeof meas[field] !== "string") {
          if (meas[field] != null) return "INVALID";
          uaFieldsPresent = false;
          continue;
        }
        const values = valuesByName.get(headerName);
        const expected = values && values.length ? values.join(", ") : "absent";
        if (meas[field] !== expected) return "INVALID";
      }
    }
    if ("round" in meas && meas.round !== 1 && meas.round !== 2) return "INVALID";

    const h2Ok = h2 && h2.status === "captured" && h2.headersStatus === "valid"
      && Array.isArray(h2.settings) && h2.settings.length > 0
      && Array.isArray(h2.settingsOrder) && h2.settingsOrder.length === h2.settings.length
      && h2.settingsEffective && typeof h2.settingsEffective === "object"
      && /^[0-9a-f]{64}$/.test(h2.settingsPayloadSha256 || "")
      && typeof h2.settingsPayloadHex === "string"
      && Array.isArray(h2.pseudoHeaderOrder) && h2.pseudoHeaderOrder.length > 0
      && Array.isArray(h2.errors) && h2.errors.length === 0;
    const transportOk = meas.alpnNegotiated === "h2" && (meas.httpVersion === "2" || meas.httpVersion === "2.0");
    // The peer address is the only non-derivable proof that the diagnostic
    // request actually used the expected proxy/network path.  Do not let a
    // capture remain CURRENT after silently dropping it.  IPv4-mapped IPv6 is
    // deliberately classified as IPv6 because that is what the accepting
    // socket observed on the wire.
    const observedIpVersion = typeof meas.observedIp === "string" ? isIP(meas.observedIp) : 0;
    const peerOk = observedIpVersion !== 0
      && meas.observedIpFamily === (observedIpVersion === 4 ? "ipv4" : "ipv6");
    const terminationOk = meas.tlsTerminatedBy === "capture-endpoint";
    const runtime = meas.captureRuntime;
    const runtimeOk = runtime && typeof runtime === "object" && !Array.isArray(runtime)
      && /^v\d+\.\d+\.\d+/.test(runtime.node || "")
      && ["v8", "openssl", "nghttp2"].every((key) => typeof runtime[key] === "string" && runtime[key].length > 0);
    const provenanceOk = /^[0-9a-f]{64}$/.test(meas.captureBuild || "")
      && meas.parserVersion === "net-v6" && runtimeOk;
    const finalRoundOk = meas.round === 2;
    const expectedAcceptCh = "platform-version,arch,bitness,model,full-version-list,wow64,form-factors";
    const hints = ["secChUa", "secChUaMobile", "secChUaPlatform", "secChUaPlatformVersion",
      "secChUaArch", "secChUaBitness", "secChUaModel", "secChUaFullVersionList", "secChUaWow64",
      "secChUaFormFactors"];
    const structuredString = /^"(?:[^"\\]|\\.)*"$/;
    const brandList = /^"(?:[^"\\]|\\.)*";v="(?:[^"\\]|\\.)*"(?:,\s*"(?:[^"\\]|\\.)*";v="(?:[^"\\]|\\.)*")*$/;
    const hintSyntax = {
      secChUa: brandList,
      secChUaMobile: /^\?[01]$/,
      secChUaPlatform: structuredString,
      secChUaPlatformVersion: structuredString,
      secChUaArch: structuredString,
      secChUaBitness: structuredString,
      secChUaModel: structuredString,
      secChUaFullVersionList: brandList,
      secChUaWow64: /^\?[01]$/,
      secChUaFormFactors: /^"(?:[^"\\]|\\.)*"(?:,\s*"(?:[^"\\]|\\.)*")*$/,
    };
    const hintsOk = meas.acceptChAdvertised === expectedAcceptCh
      && typeof meas.userAgent === "string" && meas.userAgent.length > 0
      && hints.every((key) => typeof meas[key] === "string" && meas[key] !== "absent"
        && meas[key].length > 0 && hintSyntax[key].test(meas[key]));
    return typedOk && flatOk && v6FlatPresent && h2Ok && transportOk && peerOk
      && terminationOk && provenanceOk && finalRoundOk && hintsOk && uaFieldsPresent ? "CURRENT" : "PARTIAL";
  }
  if (meas.netSchemaVersion != null) return "INVALID";
  // net-v4 legacy flat record (kept for diagnostic fixtures, never CURRENT).
  let present = 0;
  for (const k of NET_REQUIRED) if (meas[k] != null && meas[k] !== "") present++;
  return present === NET_REQUIRED.length ? "LEGACY" : present > 0 ? "PARTIAL" : "MISSING";
}
