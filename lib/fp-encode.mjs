// THE production typed-value encoder — single source of truth (Codex v4.2 #2,
// v4.3 #3). Imported by the unit test AND injected verbatim into the browser
// collector (probe / collector / SW / cross-origin xprobe) — no second copy.
//
// v4.3: LOSSLESS. Nested objects/arrays are encoded RECURSIVELY (so
// getSettings/getCapabilities/getConstraints and control components keep their
// real values, not just ctor+keys). Cycles are marked, not fatal. Buffers carry a
// real SHA-256 (sync pure-JS, so it works even in audio-worklet where
// crypto.subtle is absent). No silent truncation: an oversized encoded value
// becomes a blobRef{length,sha256,fnv,preview}; array/key caps are marked.
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
// UTF-8 bytes of a string (no TextEncoder dependency — audio-worklet-safe).
function utf8Bytes(str) {
  var out = [], i, c;
  for (i = 0; i < str.length; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      var c2 = str.charCodeAt(i + 1);
      var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff); i++;
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
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

// ---- lossless encoder ---------------------------------------------------
// blobRef / cycle markers are embedded IN `value` (as {__blobRef} / {__cycle}) so
// every record-building call site can keep storing `enc.value` unchanged; the
// schema validator recognises these markers for any valueType.
var MAX_DEPTH = 8, MAX_KEYS = 512, MAX_ARR = 8192, MAX_STR = 16384, MAX_INLINE_JSON = 65536;
function blobRef(kind, len, hashInput) {
  return { __blobRef: { kind: kind, length: len, sha256: sha256hex(hashInput), fnv: fnv1a(hashInput),
    preview: (typeof hashInput === "string" ? hashInput.slice(0, 256) : null) } };
}

function enc(v, depth, seen) {
  var t = typeof v;
  if (v === null) return { valueType: "null", value: null };
  if (t === "undefined") return { valueType: "undefined", value: null };
  if (t === "boolean") return { valueType: "boolean", value: v };
  if (t === "string") {
    if (v.length > MAX_STR) return { valueType: "string", value: blobRef("string", v.length, v) };
    return { valueType: "string", value: v };
  }
  if (t === "number") {
    if (v !== v) return { valueType: "number", value: null, special: "NaN" };
    if (v === Infinity) return { valueType: "number", value: null, special: "Infinity" };
    if (v === -Infinity) return { valueType: "number", value: null, special: "-Infinity" };
    if (v === 0 && 1 / v === -Infinity) return { valueType: "number", value: 0, special: "-0" };
    return { valueType: "number", value: v };
  }
  if (t === "bigint") return { valueType: "bigint", value: v.toString() };
  if (t === "symbol") return { valueType: "symbol", value: v.toString() };
  if (t === "function") return { valueType: "function", value: (v.name || "") + "/" + v.length };
  if (typeof ArrayBuffer !== "undefined" && v instanceof ArrayBuffer) {
    var ab = new Uint8Array(v);
    return { valueType: "arraybuffer", value: { byteLength: v.byteLength, contentHash: bytesHash(ab), sha256: sha256hex(ab) } };
  }
  if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(v)) {
    var u8 = (v instanceof Uint8Array) ? v : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    return { valueType: "typedarray", value: { ctor: (v.constructor && v.constructor.name) || "", length: (v.length != null ? v.length : v.byteLength), byteLength: v.byteLength, contentHash: bytesHash(u8), sha256: sha256hex(u8) } };
  }
  if (v instanceof Error) return { valueType: "error", value: { name: v.name, message: v.message, stack: v.stack ? String(v.stack).split("\n").slice(0, 3).join(" | ") : null } };

  // objects & arrays — recurse own enumerable props with a cycle guard on the
  // ancestor chain (delete on unwind so a diamond isn't mistaken for a cycle).
  if (seen) { if (seen.has(v)) return { valueType: Array.isArray(v) ? "array" : "object", value: { __cycle: true } }; seen.add(v); }
  var res;
  if (Array.isArray(v)) {
    if (depth >= MAX_DEPTH) res = { valueType: "array", value: null, count: v.length };
    else {
      var n = Math.min(v.length, MAX_ARR), arr = [];
      for (var i = 0; i < n; i++) arr.push(enc(v[i], depth + 1, seen));
      res = { valueType: "array", value: arr, count: v.length };   // count > value.length ⇒ capped (marked, not silent)
    }
  } else {
    var ctor = ""; try { ctor = (v.constructor && v.constructor.name) || ""; } catch (_) {}
    if (depth >= MAX_DEPTH) res = { valueType: "object", value: { __ctor: ctor, __maxDepth: true } };
    else {
      var keys; try { keys = Object.keys(v); } catch (_) { keys = []; }
      var props = {}, kn = Math.min(keys.length, MAX_KEYS);
      for (var j = 0; j < kn; j++) {
        var k = keys[j], pv;
        try { pv = v[k]; } catch (e) { props[k] = { valueType: "error", value: { name: (e && e.name) || "GetterError", message: (e && e.message) || "" } }; continue; }
        props[k] = enc(pv, depth + 1, seen);
      }
      res = { valueType: "object", value: { __ctor: ctor, props: props } };
      if (keys.length > MAX_KEYS) res.value.__truncatedKeys = keys.length;
    }
  }
  if (seen) seen.delete(v);
  return res;
}

/** Encode a value into a lossless, clone- and JSON-safe typed record value. */
export function encodeValue(v) {
  var res = enc(v, 0, (typeof WeakSet !== "undefined") ? new WeakSet() : null);
  // Oversize guard (measured once on the whole encoded tree): swap a huge payload
  // for a blobRef so it never bloats every record inline. Marker rides in `value`.
  if (res && (res.valueType === "object" || res.valueType === "array") && res.value != null && !res.value.__blobRef && !res.value.__cycle) {
    var js; try { js = JSON.stringify(res.value); } catch (_) { js = null; }
    if (js && js.length > MAX_INLINE_JSON) {
      var out = { valueType: res.valueType, value: blobRef(res.valueType, js.length, js) };
      if (res.count != null) out.count = res.count;
      out.value.__blobRef.preview = js.slice(0, 256);
      return out;
    }
  }
  return res;
}
