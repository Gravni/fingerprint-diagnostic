// THE production typed-value encoder — single source of truth (Codex v4.2 #2,
// v4.3 #3). Imported by the unit test AND injected verbatim into the browser
// collector (probe / collector / SW / cross-origin xprobe) — no second copy.
//
// This is a BOUNDED encoder, not a lossless serializer. Nested objects/arrays are
// encoded recursively while they fit the documented limits. Anything outside a
// limit becomes an explicit blobRef: content-addressed when its canonical
// observation fits the secondary safety budget, otherwise visibly marked
// `complete:false`. Callers can persist emitted payloads synchronously through
// `options.blobSink`.
// Cycles carry an ancestor reference, and buffers carry a real SHA-256 (sync
// pure-JS, so it works even where crypto.subtle is absent).
//
// Output is always plain JSON- and structured-clone-safe data (no live refs, no
// functions) — the anti-hang guarantee. Keep it ES5-compatible and dependency-free.

// ---- hashes -------------------------------------------------------------
export function fnv1a(s) {
  var h = 0x811c9dc5;
  for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; }
  return ("00000000" + h.toString(16)).slice(-8);
}
export function bytesHash(b) {
  var h = 0x811c9dc5;
  for (var i = 0; i < b.length; i++) { h ^= (b[i] & 0xff); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; }
  return ("00000000" + h.toString(16)).slice(-8);
}
// WHATWG UTF-8 bytes of a string (no TextEncoder dependency —
// audio-worklet-safe). TextEncoder replaces every unpaired UTF-16 surrogate
// with U+FFFD; matching that rule is important because the digest must agree
// across browser and Node implementations.
function utf8Bytes(str) {
  var out = [], i, c;
  for (i = 0; i < str.length; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c >= 0xd800 && c <= 0xdbff) {
      var c2 = (i + 1 < str.length) ? str.charCodeAt(i + 1) : 0;
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff); i++;
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      } else out.push(0xef, 0xbf, 0xbd);
    } else if (c >= 0xdc00 && c <= 0xdfff) out.push(0xef, 0xbf, 0xbd);
    else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
  }
  return out;
}
// FIPS 180-4 SHA-256 over a byte array → hex. Sync; works in every realm.
function sha256bytes(bytes) {
  function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l = bytes.length, msg = new Array(l);
  for (var i0 = 0; i0 < l; i0++) msg[i0] = bytes[i0] & 0xff;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  var bitHi = Math.floor(l / 0x20000000), bitLo = (l * 8) >>> 0;
  msg.push((bitHi >>> 24) & 0xff, (bitHi >>> 16) & 0xff, (bitHi >>> 8) & 0xff, bitHi & 0xff);
  msg.push((bitLo >>> 24) & 0xff, (bitLo >>> 16) & 0xff, (bitLo >>> 8) & 0xff, bitLo & 0xff);
  var w = new Array(64);
  for (var off = 0; off < msg.length; off += 64) {
    for (var t = 0; t < 16; t++) w[t] = (msg[off + t * 4] << 24) | (msg[off + t * 4 + 1] << 16) | (msg[off + t * 4 + 2] << 8) | (msg[off + t * 4 + 3]);
    for (t = 16; t < 64; t++) {
      var s0 = rotr(7, w[t - 15]) ^ rotr(18, w[t - 15]) ^ (w[t - 15] >>> 3);
      var s1 = rotr(17, w[t - 2]) ^ rotr(19, w[t - 2]) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (t = 0; t < 64; t++) {
      var S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      var ch = (e & f) ^ ((~e) & g);
      var temp1 = (h + S1 + ch + K[t] + w[t]) | 0;
      var S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var temp2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  var hex = "";
  for (i0 = 0; i0 < 8; i0++) hex += ("00000000" + (H[i0] >>> 0).toString(16)).slice(-8);
  return hex;
}
/** SHA-256 hex of a string (UTF-8) or byte array-like. Sync, all realms. */
export function sha256hex(input) {
  if (typeof input === "string") return sha256bytes(utf8Bytes(input));
  if (input && typeof input.length === "number") return sha256bytes(input);
  return sha256bytes([]);
}

// ---- bounded typed encoder ---------------------------------------------
// blobRef / cycle markers are embedded IN `value` (as {__blobRef} / {__cycle}) so
// every record-building call site can keep storing `enc.value` unchanged; the
// schema validator recognises these markers for any valueType.
var MAX_DEPTH = 8, MAX_KEYS = 512, MAX_ARR = 8192, MAX_STR = 16384, MAX_INLINE_JSON = 65536;
var MAX_CANONICAL_STEPS = 12000, MAX_CANONICAL_STRING_UNITS = 262144;
var MAX_TOTAL_NODES = 10000, MAX_TOTAL_STRING_UNITS = 262144, MAX_BINARY_BYTES = 1048576;

function pointerChild(path, key) {
  return path + "/" + String(key).replace(/~/g, "~0").replace(/\//g, "~1");
}

// Canonical representation used only for blob addressing. It covers every own
// enumerable value, preserves array holes/order, distinguishes special numbers,
// and records graph identity/cycles. It deliberately does not call toJSON or an
// arbitrary object's toString(). "complete" on a ref therefore means complete
// for the encoder's own-enumerable observation model, not a dump of hidden
// native slots.
function canonicalPayload(root) {
  var seen = (typeof WeakMap !== "undefined") ? new WeakMap() : null;
  var seenValues = [], seenIds = [], nextId = 0, steps = 0, stringUnits = 0;

  function spend(stepCount, unitCount) {
    steps += stepCount || 0; stringUnits += unitCount || 0;
    if (steps > MAX_CANONICAL_STEPS || stringUnits > MAX_CANONICAL_STRING_UNITS) {
      var budgetError = new Error("canonical observation budget exceeded");
      budgetError.name = "CanonicalBudgetError";
      throw budgetError;
    }
  }

  function seenId(v) {
    if (seen) return seen.has(v) ? seen.get(v) : null;
    for (var z = 0; z < seenValues.length; z++) if (seenValues[z] === v) return seenIds[z];
    return null;
  }
  function remember(v, id) {
    if (seen) seen.set(v, id);
    else { seenValues.push(v); seenIds.push(id); }
  }
  function ser(v) {
    var t = typeof v;
    spend(1, t === "string" ? v.length : 0);
    if (v === null) return "null";
    if (t === "undefined") return "undefined";
    if (t === "boolean") return v ? "true" : "false";
    if (t === "string") return "string:" + JSON.stringify(v);
    if (t === "number") {
      if (v !== v) return "number:NaN";
      if (v === Infinity) return "number:+Infinity";
      if (v === -Infinity) return "number:-Infinity";
      if (v === 0 && 1 / v === -Infinity) return "number:-0";
      return "number:" + String(v);
    }
    if (t === "bigint") { var bigText = safeScalarString(v); spend(0, bigText.length); return "bigint:" + bigText; }
    if (t === "symbol") { var symbolText = safeScalarString(v); spend(0, symbolText.length); return "symbol:" + JSON.stringify(symbolText); }
    if (t === "function") return "function:" + ser(safeFunctionSignature(v, null));

    var prior = seenId(v);
    if (prior !== null) return "ref:" + prior;
    var id = nextId++; remember(v, id);

    if (typeof ArrayBuffer !== "undefined" && v instanceof ArrayBuffer) {
      if (v.byteLength > MAX_BINARY_BYTES) throw new Error("canonical binary budget exceeded");
      var ab = new Uint8Array(v);
      return "arraybuffer#" + id + ":" + v.byteLength + ":" + sha256hex(ab);
    }
    if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(v)) {
      if (v.byteLength > MAX_BINARY_BYTES) throw new Error("canonical binary budget exceeded");
      var vu8 = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      var vctor = ""; try { vctor = (v.constructor && v.constructor.name) || ""; } catch (_) {}
      return "typedarray#" + id + ":" + JSON.stringify(vctor) + ":" + v.byteLength + ":" + sha256hex(vu8);
    }
    if (v instanceof Error) {
      return "error#" + id + ":" + ser(encodeErrorValue(v, null).value);
    }
    if (Array.isArray(v)) {
      var canonicalArrayLength = v.length;
      if (typeof canonicalArrayLength !== "number" || !isFinite(canonicalArrayLength) ||
          Math.floor(canonicalArrayLength) !== canonicalArrayLength || canonicalArrayLength < 0 ||
          canonicalArrayLength > 0xffffffff) throw new TypeError("invalid canonical array length");
      var ap = ["array#" + id + ":" + canonicalArrayLength + "["];
      for (var ai = 0; ai < canonicalArrayLength; ai++) {
        if (Object.prototype.hasOwnProperty.call(v, ai)) {
          var item, itemError = null;
          try { item = v[ai]; } catch (ie) { itemError = ie; }
          ap.push(itemError ? "getter-error:" + JSON.stringify(describeThrown(itemError, null)) : ser(item), ",");
        } else { spend(1, 0); ap.push("hole,"); }
      }
      var akeys = Object.keys(v);
      var extras = [];
      for (var ax = 0; ax < akeys.length; ax++) {
        var ak = akeys[ax];
        if (/^(0|[1-9]\d*)$/.test(ak) && +ak < canonicalArrayLength && String(+ak) === ak) continue;
        spend(0, ak.length);
        var av, araw, aget = null;
        try { araw = v[ak]; } catch (ae) { aget = ae; }
        if (aget) av = "getter-error:" + JSON.stringify(describeThrown(aget, null));
        else av = ser(araw);
        extras.push(JSON.stringify(ak) + ":" + av);
      }
      if (typeof Object.getOwnPropertySymbols === "function") {
        var asyms = Object.getOwnPropertySymbols(v);
        for (var asi = 0; asi < asyms.length; asi++) {
          var asym = asyms[asi], adesc = Object.getOwnPropertyDescriptor(v, asym);
          if (!adesc || !adesc.enumerable) continue;
          var asv, asError = null;
          try { asv = v[asym]; } catch (ase) { asError = ase; }
          var asymText = safeScalarString(asym); spend(0, asymText.length);
          extras.push("symbol:" + JSON.stringify(asymText) + ":" +
            (asError ? "getter-error:" + JSON.stringify(describeThrown(asError, null)) : ser(asv)));
        }
      }
      ap.push("]{" + extras.join(",") + "}");
      return ap.join("");
    }

    var ctor = "", tag = "";
    try { ctor = (v.constructor && v.constructor.name) || ""; } catch (_) {}
    try { tag = Object.prototype.toString.call(v); } catch (_) {}
    var keys = Object.keys(v);
    var op = ["object#" + id + ":" + JSON.stringify(ctor) + ":" + JSON.stringify(tag) + "{"];
    for (var oi = 0; oi < keys.length; oi++) {
      var k = keys[oi], ov, raw, getError = null;
      spend(0, k.length);
      try { raw = v[k]; } catch (oe) { getError = oe; }
      if (getError) ov = "getter-error:" + JSON.stringify(describeThrown(getError, null));
      else ov = ser(raw);
      op.push(JSON.stringify(k), ":", ov, ",");
    }
    if (typeof Object.getOwnPropertySymbols === "function") {
      var syms = Object.getOwnPropertySymbols(v);
      for (var syi = 0; syi < syms.length; syi++) {
        var sym = syms[syi], desc = Object.getOwnPropertyDescriptor(v, sym);
        if (!desc || !desc.enumerable) continue;
        var sv, symError = null;
        try { sv = v[sym]; } catch (se) { symError = se; }
        var symText = safeScalarString(sym); spend(0, symText.length);
        op.push("symbol:", JSON.stringify(symText), ":",
          symError ? "getter-error:" + JSON.stringify(describeThrown(symError, null)) : ser(sv), ",");
      }
    }
    op.push("}");
    return op.join("");
  }
  return ser(root);
}

function persistBlob(kind, len, payload, reason, options, encoding, complete, lengthUnit) {
  var addressVersion = "fp-blob-address-v1";
  var addressPayload = addressVersion + "\u0000" + encoding + "\u0000" + payload;
  var sha = sha256hex(payload), addressSha = sha256hex(addressPayload);
  var fnv = fnv1a(payload), addressFnv = fnv1a(addressPayload);
  var isComplete = complete !== false;
  var ref = { kind: kind, length: len, sha256: sha, addressSha256: addressSha,
    fnv: fnv, addressFnv: addressFnv,
    preview: (typeof payload === "string" ? payload.slice(0, 256) : null),
    reason: reason, encoding: encoding, addressVersion: addressVersion, complete: isComplete,
    hashScope: isComplete ? "content" : "marker",
    lengthUnit: lengthUnit || "units", stored: false };
  var sink = options && options.blobSink;
  if (typeof sink === "function") {
    try {
      var stored = sink({ kind: kind, length: len, sha256: sha, addressSha256: addressSha,
        fnv: fnv, addressFnv: addressFnv,
        reason: reason, encoding: encoding, addressVersion: addressVersion, complete: isComplete,
        hashScope: isComplete ? "content" : "marker",
        lengthUnit: lengthUnit || "units", payload: payload });
      if (typeof stored === "string" && stored) { ref.locator = stored; ref.stored = true; }
      else if (stored && typeof stored === "object" && typeof stored.locator === "string" && stored.locator) {
        ref.locator = stored.locator; ref.stored = stored.stored !== false;
      }
    } catch (e) {
      ref.sinkError = describeThrown(e, null);
    }
  }
  return { __blobRef: ref };
}

function incompleteBlobRef(kind, len, reason, options, lengthUnit) {
  var marker = "fp-truncation-marker-v1|" + kind + "|" + len + "|" + reason + "|content-not-addressed";
  return persistBlob(kind, len, marker, reason, options, "fp-truncation-marker-v1", false, lengthUnit);
}

function hasUnpairedSurrogate(s) {
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      var n = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (n >= 0xdc00 && n <= 0xdfff) i++;
      else return true;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

function stringBlobRef(value, reason, options) {
  if (value.length > MAX_CANONICAL_STRING_UNITS) {
    return incompleteBlobRef("string", value.length, reason, options, "utf16-code-units");
  }
  // WHATWG UTF-8 intentionally maps an unpaired surrogate and U+FFFD to the
  // same bytes. JSON escaping is reversible, so use it only for ill-formed
  // UTF-16 strings while retaining the historical raw UTF-8 digest otherwise.
  var illFormed = hasUnpairedSurrogate(value);
  var payload = illFormed ? JSON.stringify(value) : value;
  return persistBlob("string", value.length, payload, reason, options,
    illFormed ? "json-string-v1" : "utf-8", true, "utf16-code-units");
}

function safeScalarString(v) {
  var t = typeof v;
  if (t === "string") return v;
  if (t === "undefined") return "undefined";
  if (v === null) return "null";
  if (t === "symbol") { try { return Symbol.prototype.toString.call(v); } catch (_) { return "Symbol(?)"; } }
  if (t === "bigint" || t === "number" || t === "boolean") return String(v);
  try { return Object.prototype.toString.call(v); } catch (_) { return "[unprintable " + t + "]"; }
}

function compactBlobMarker(ref) {
  var compact = { kind: ref.kind, length: ref.length, lengthUnit: ref.lengthUnit,
    sha256: ref.sha256, addressSha256: ref.addressSha256,
    reason: ref.reason, encoding: ref.encoding,
    complete: ref.complete, hashScope: ref.hashScope, stored: ref.stored };
  if (ref.locator) compact.locator = ref.locator;
  return "[blobRef:" + JSON.stringify(compact) + "]";
}

function boundedThrownPart(text, label, options) {
  if (text.length <= 1024) return text;
  return compactBlobMarker(stringBlobRef(text, "thrown-" + label + "-limit", options).__blobRef);
}

function describeThrown(error, options) {
  if (error === null || (typeof error !== "object" && typeof error !== "function")) {
    return "Thrown: " + boundedThrownPart(safeScalarString(error), "value", options);
  }
  var name = "Error", message = "";
  try { name = safeScalarString(error.name || "Error"); } catch (_) {}
  try { message = safeScalarString(error.message || ""); } catch (_) {}
  name = boundedThrownPart(name, "name", options);
  message = boundedThrownPart(message, "message", options);
  return name + (message ? ": " + message : "");
}

function safeTextField(obj, key, fallback, options) {
  var raw;
  try { raw = obj[key]; }
  catch (e) { return { text: fallback, error: describeThrown(e, options) }; }
  if (raw === undefined) return { text: fallback };
  if (raw == null && key === "stack") return { text: null };
  var text = safeScalarString(raw);
  if (text.length <= MAX_STR) return { text: text };
  var marker = stringBlobRef(text, "error-" + key + "-limit", options).__blobRef;
  return { text: "[blob:" + marker.sha256 + "]", ref: marker };
}

function encodeErrorValue(error, options) {
  var name = safeTextField(error, "name", "Error", options);
  var message = safeTextField(error, "message", "", options);
  var stack = safeTextField(error, "stack", null, options);
  var value = { name: name.text || "Error", message: message.text == null ? "" : message.text, stack: stack.text };
  var fieldErrors = {};
  if (name.error) fieldErrors.name = name.error;
  if (message.error) fieldErrors.message = message.error;
  if (stack.error) fieldErrors.stack = stack.error;
  if (Object.keys(fieldErrors).length) value.fieldErrors = fieldErrors;
  if (name.ref) value.nameRef = name.ref;
  if (message.ref) value.messageRef = message.ref;
  if (stack.ref) value.stackRef = stack.ref;
  return { valueType: "error", value: value };
}

function safeFunctionSignature(fn, options) {
  var name, arity, nameError = null, lengthError = null;
  try { name = safeScalarString(fn.name || ""); } catch (e) { nameError = e; }
  try { arity = safeScalarString(fn.length); } catch (e) { lengthError = e; }
  var namePart = nameError ? "[name-error:" + describeThrown(nameError, options).split(":")[0] + "]" : name;
  var lengthPart = lengthError ? "[length-error:" + describeThrown(lengthError, options).split(":")[0] + "]" : arity;
  var text = namePart + "/" + lengthPart;
  if (text.length <= MAX_STR) return { text: text, ref: null };
  var marker = stringBlobRef(text, "function-signature-limit", options).__blobRef;
  return { text: compactBlobMarker(marker), ref: marker };
}

function valueBlobRef(kind, value, len, reason, options) {
  var lengthUnit = kind === "array" ? "elements" : "own-enumerable-keys";
  try {
    return persistBlob(kind, len, canonicalPayload(value), reason, options, "fp-canonical-v1", true, lengthUnit);
  } catch (_) {
    // Exact addressing and bounded execution cannot both be guaranteed for an
    // adversarially huge/deep graph. Make the degradation machine-readable and
    // never pretend this marker's digest addresses the omitted content.
    return incompleteBlobRef(kind, len, reason, options, lengthUnit);
  }
}

function incompleteEncodedValue(v, reason, options) {
  var t = typeof v;
  if (t === "string") return { valueType: "string", value: incompleteBlobRef("string", v.length, reason, options, "utf16-code-units") };
  if (Array.isArray(v)) {
    var alen = 0; try { alen = v.length; } catch (_) {}
    return { valueType: "array", value: incompleteBlobRef("array", alen, reason, options, "elements"), count: alen };
  }
  return { valueType: "object", value: incompleteBlobRef("object", 0, reason, options, "own-enumerable-keys") };
}

function incompleteBinaryValue(originalValueType, byteLength, reason, options) {
  var value = incompleteBlobRef("object", byteLength, reason, options, "bytes");
  value.__blobRef.originalValueType = originalValueType;
  return { valueType: "object", value: value };
}

function boundedOpaqueScalar(originalValueType, text, reason, options) {
  if (text.length <= MAX_STR) return { valueType: originalValueType, value: text };
  var value;
  if (text.length > MAX_CANONICAL_STRING_UNITS) {
    value = incompleteBlobRef("object", text.length, reason, options, "utf16-code-units");
  } else {
    value = persistBlob("object", text.length, text, reason, options,
      originalValueType + "-string-v1", true, "utf16-code-units");
  }
  value.__blobRef.originalValueType = originalValueType;
  return { valueType: "object", value: value };
}

function spendInline(state, stringUnits) {
  state.nodes++;
  state.stringUnits += stringUnits || 0;
  if (state.nodes > MAX_TOTAL_NODES || state.stringUnits > MAX_TOTAL_STRING_UNITS) state.exhausted = true;
  return !state.exhausted;
}

function enc(v, depth, ancestors, path, options, state) {
  var t = typeof v;
  var withinBudget = spendInline(state, t === "string" ? v.length : 0);
  if (v === null) return { valueType: "null", value: null };
  if (t === "undefined") return { valueType: "undefined", value: null };
  if (t === "boolean") return { valueType: "boolean", value: v };
  if (t === "string") {
    if (!withinBudget) return incompleteEncodedValue(v, "total-inline-budget", options);
    if (v.length > MAX_STR) return { valueType: "string", value: stringBlobRef(v, "string-limit", options) };
    return { valueType: "string", value: v };
  }
  if (t === "number") {
    if (v !== v) return { valueType: "number", value: null, special: "NaN" };
    if (v === Infinity) return { valueType: "number", value: null, special: "Infinity" };
    if (v === -Infinity) return { valueType: "number", value: null, special: "-Infinity" };
    if (v === 0 && 1 / v === -Infinity) return { valueType: "number", value: 0, special: "-0" };
    return { valueType: "number", value: v };
  }
  if (t === "bigint") return boundedOpaqueScalar("bigint", safeScalarString(v), "bigint-string-limit", options);
  if (t === "symbol") return boundedOpaqueScalar("symbol", safeScalarString(v), "symbol-string-limit", options);
  if (t === "function") {
    var signature = safeFunctionSignature(v, options);
    var functionResult = { valueType: "function", value: signature.text };
    if (signature.ref) functionResult.signatureRef = signature.ref;
    return functionResult;
  }
  if (typeof ArrayBuffer !== "undefined" && v instanceof ArrayBuffer) {
    var abLength = 0, ab;
    try { abLength = v.byteLength; } catch (_) { return incompleteBinaryValue("arraybuffer", 0, "arraybuffer-length-error", options); }
    if (abLength > MAX_BINARY_BYTES) return incompleteBinaryValue("arraybuffer", abLength, "binary-byte-budget", options);
    try { ab = new Uint8Array(v); }
    catch (_) { return incompleteBinaryValue("arraybuffer", abLength, "arraybuffer-read-error", options); }
    return { valueType: "arraybuffer", value: { byteLength: abLength, contentHash: bytesHash(ab), sha256: sha256hex(ab) } };
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(v)) {
    var viewByteLength = 0, viewLength = 0, ctorName = "", ctorError = null, u8;
    try { viewByteLength = v.byteLength; } catch (_) { return incompleteBinaryValue("typedarray", 0, "typedarray-length-error", options); }
    if (viewByteLength > MAX_BINARY_BYTES) return incompleteBinaryValue("typedarray", viewByteLength, "binary-byte-budget", options);
    try { viewLength = v.length != null ? v.length : viewByteLength; } catch (_) { viewLength = viewByteLength; }
    try { ctorName = (v.constructor && v.constructor.name) || ""; }
    catch (ce) { ctorError = ce; ctorName = "[constructor-error:" + describeThrown(ce, options).split(":")[0] + "]"; }
    try { u8 = new Uint8Array(v.buffer, v.byteOffset, viewByteLength); }
    catch (_) { return incompleteBinaryValue("typedarray", viewByteLength, "typedarray-read-error", options); }
    var typedValue = { ctor: safeScalarString(ctorName), length: viewLength, byteLength: viewByteLength,
      contentHash: bytesHash(u8), sha256: sha256hex(u8) };
    if (ctorError) typedValue.ctorError = describeThrown(ctorError, options);
    return { valueType: "typedarray", value: typedValue };
  }
  if (v instanceof Error) return encodeErrorValue(v, options);

  // objects & arrays — recurse own enumerable props with a cycle guard on the
  // ancestor chain (pop on unwind so a diamond isn't mistaken for a cycle).
  var priorPath = null;
  for (var si = ancestors.length - 1; si >= 0; si--) {
    if (ancestors[si].value === v) { priorPath = ancestors[si].path; break; }
  }
  if (priorPath !== null) return {
    valueType: Array.isArray(v) ? "array" : "object",
    value: { __cycle: true },
    cycleRef: priorPath,
  };
  if (!withinBudget) return incompleteEncodedValue(v, "total-inline-budget", options);
  ancestors.push({ value: v, path: path });
  var res;
  if (Array.isArray(v)) {
    var arrLength = 0, arrayLengthError = null, arrayKeys, arrayKeysError = null;
    try { arrLength = v.length; } catch (ale) { arrayLengthError = ale; }
    if (!arrayLengthError && (typeof arrLength !== "number" || !isFinite(arrLength) ||
        Math.floor(arrLength) !== arrLength || arrLength < 0 || arrLength > 0xffffffff)) {
      arrayLengthError = new TypeError("invalid array length"); arrLength = 0;
    }
    try { arrayKeys = Object.keys(v); } catch (ake) { arrayKeysError = ake; arrayKeys = []; }
    var hasArrayExtras = false;
    for (var aki = 0; aki < arrayKeys.length; aki++) {
      var arrayKey = arrayKeys[aki];
      if (!(/^(0|[1-9]\d*)$/.test(arrayKey) && +arrayKey < arrLength && String(+arrayKey) === arrayKey)) { hasArrayExtras = true; break; }
    }
    var hasArraySymbols = false, arraySymbolsError = null;
    if (typeof Object.getOwnPropertySymbols === "function") {
      try {
        var arraySymbols = Object.getOwnPropertySymbols(v);
        for (var as = 0; as < arraySymbols.length; as++) {
          var arrayDesc = Object.getOwnPropertyDescriptor(v, arraySymbols[as]);
          if (arrayDesc && arrayDesc.enumerable) { hasArraySymbols = true; break; }
        }
      } catch (ase) { arraySymbolsError = ase; }
    }
    if (arrayLengthError) res = { valueType: "array", value: incompleteBlobRef("array", 0, "array-length-error", options, "elements"), count: 0 };
    else if (arrayKeysError || arraySymbolsError) res = { valueType: "array", value: incompleteBlobRef("array", arrLength, "array-keys-error", options, "elements"), count: arrLength };
    else if (hasArrayExtras || hasArraySymbols) res = { valueType: "array", value: valueBlobRef("array", v, arrLength, "array-extra-properties", options), count: arrLength };
    else if (depth >= MAX_DEPTH) res = { valueType: "array", value: valueBlobRef("array", v, arrLength, "max-depth", options), count: arrLength };
    else if (arrLength > MAX_ARR) res = { valueType: "array", value: valueBlobRef("array", v, arrLength, "array-limit", options), count: arrLength };
    else {
      var arr = [], arrayBudgetExceeded = false;
      for (var i = 0; i < arrLength; i++) {
        if (state.exhausted) { arrayBudgetExceeded = true; break; }
        var hasItem = false, hasItemError = null;
        try { hasItem = Object.prototype.hasOwnProperty.call(v, i); } catch (hie) { hasItemError = hie; }
        if (hasItemError) { arr.push(encodeErrorValue(hasItemError, options)); continue; }
        if (hasItem) {
          var item, itemReadError = null;
          try { item = v[i]; } catch (ire) { itemReadError = ire; }
          arr.push(itemReadError ? encodeErrorValue(itemReadError, options) : enc(item, depth + 1, ancestors, pointerChild(path, i), options, state));
        }
        else arr.push({ valueType: "undefined", value: null, hole: true });
      }
      res = arrayBudgetExceeded || state.exhausted
        ? { valueType: "array", value: incompleteBlobRef("array", arrLength, "total-inline-budget", options, "elements"), count: arrLength }
        : { valueType: "array", value: arr, count: arrLength };
    }
  } else {
    var ctor = ""; try { ctor = (v.constructor && v.constructor.name) || ""; } catch (_) {}
    var keys, keysError = null; try { keys = Object.keys(v); } catch (oke) { keysError = oke; keys = []; }
    var symbolKeys = [], symbolKeysError = null;
    if (typeof Object.getOwnPropertySymbols === "function") {
      try {
        var allSymbols = Object.getOwnPropertySymbols(v);
        for (var sk = 0; sk < allSymbols.length; sk++) {
          var symbolDesc = Object.getOwnPropertyDescriptor(v, allSymbols[sk]);
          if (symbolDesc && symbolDesc.enumerable) symbolKeys.push(allSymbols[sk]);
        }
      } catch (ske) { symbolKeysError = ske; }
    }
    if (keysError) res = { valueType: "object", value: incompleteBlobRef("object", 0, "object-keys-error", options, "own-enumerable-keys") };
    else if (symbolKeysError) res = { valueType: "object", value: incompleteBlobRef("object", keys.length, "object-symbol-keys-error", options, "own-enumerable-keys") };
    else if (symbolKeys.length) res = { valueType: "object", value: valueBlobRef("object", v, keys.length + symbolKeys.length, "object-symbol-keys", options) };
    else if (depth >= MAX_DEPTH) res = { valueType: "object", value: valueBlobRef("object", v, keys.length, "max-depth", options) };
    else if (keys.length > MAX_KEYS) res = { valueType: "object", value: valueBlobRef("object", v, keys.length, "object-key-limit", options) };
    else {
      // A null prototype is required here: an observed own key named
      // "__proto__" must remain data instead of mutating the result object.
      var props = Object.create(null);
      var objectBudgetExceeded = false;
      for (var j = 0; j < keys.length; j++) {
        if (state.exhausted) { objectBudgetExceeded = true; break; }
        var k = keys[j], pv;
        state.stringUnits += k.length;
        if (state.stringUnits > MAX_TOTAL_STRING_UNITS) { state.exhausted = true; objectBudgetExceeded = true; break; }
        try { pv = v[k]; } catch (e) { props[k] = encodeErrorValue(e, options); continue; }
        props[k] = enc(pv, depth + 1, ancestors, pointerChild(path, k), options, state);
      }
      res = objectBudgetExceeded || state.exhausted
        ? { valueType: "object", value: incompleteBlobRef("object", keys.length, "total-inline-budget", options, "own-enumerable-keys") }
        : { valueType: "object", value: { __ctor: ctor, props: props } };
    }
  }
  ancestors.pop();
  return res;
}

/**
 * Encode a value into a bounded, clone- and JSON-safe typed record value.
 *
 * `options.blobSink` may synchronously persist payloads omitted from the inline
 * record. It receives the exact canonical payload when `complete:true`, or an
 * explicit bounded marker when `complete:false`, and may return a locator string
 * or `{locator,stored}`. Calls without options remain fully backward compatible;
 * every ref advertises `stored:false` so nobody mistakes a digest for retained
 * bytes.
 */
export function encodeValue(v, options) {
  var state = { nodes: 0, stringUnits: 0, exhausted: false };
  var res = enc(v, 0, [], "#", options || null, state);
  if (state.exhausted && (typeof v === "string" || (v !== null && typeof v === "object"))) {
    if (res && res.value && res.value.__blobRef && res.value.__blobRef.reason === "total-inline-budget") return res;
    return incompleteEncodedValue(v, "total-inline-budget", options || null);
  }
  // Oversize guard (measured once on the whole encoded tree): swap a huge payload
  // for a blobRef so it never bloats every record inline. Marker rides in `value`.
  if (res && (res.valueType === "object" || res.valueType === "array") && res.value != null && !res.value.__blobRef && !res.value.__cycle) {
    var js; try { js = JSON.stringify(res.value); } catch (_) { js = null; }
    if (js && js.length > MAX_INLINE_JSON) {
      var out = { valueType: res.valueType, value: persistBlob(res.valueType, js.length, js, "inline-json-limit", options, "fp-encoded-json-v1", true, "encoded-json-utf16-code-units") };
      if (res.count != null) out.count = res.count;
      return out;
    }
  }
  return res;
}
