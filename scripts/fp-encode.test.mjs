// Regression test for the PRODUCTION typed-value encoder (lib/fp-encode.mjs) —
// the ONE source the browser collector also runs. v4.3: LOSSLESS nested encoding,
// cycles, function/symbol in arrays, DataView/ArrayBuffer/typed arrays, and a
// sync SHA-256 verified against node crypto.

import { encodeValue, fnv1a, bytesHash, sha256hex } from "../lib/fp-encode.mjs";
import { createHash } from "node:crypto";

let pass = 0, fail = 0;
function eq(label, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { pass++; } else { fail++; console.log(`  ✗ ${label}\n      got  ${g}\n      want ${w}`); }
}
function ok(label, cond) { if (cond) pass++; else { fail++; console.log(`  ✗ ${label}`); } }
const nodeSha = (x) => createHash("sha256").update(x).digest("hex");

// ---- native types preserved ---------------------------------------------
eq("false → boolean false", encodeValue(false), { valueType: "boolean", value: false });
eq("null", encodeValue(null), { valueType: "null", value: null });
eq("undefined", encodeValue(undefined), { valueType: "undefined", value: null });
eq('string "false"', encodeValue("false"), { valueType: "string", value: "false" });
eq("NaN", encodeValue(NaN), { valueType: "number", value: null, special: "NaN" });
eq("Infinity", encodeValue(Infinity), { valueType: "number", value: null, special: "Infinity" });
eq("-0", encodeValue(-0), { valueType: "number", value: 0, special: "-0" });
eq("42", encodeValue(42), { valueType: "number", value: 42 });
eq("bigint", encodeValue(10n), { valueType: "bigint", value: "10" });
eq("function → name/arity", encodeValue(function foo(a, b) {}), { valueType: "function", value: "foo/2" });
{ const r = encodeValue(Symbol("s")); ok("symbol → symbol", r.valueType === "symbol" && /Symbol\(s\)/.test(r.value)); }

// ---- LOSSLESS nested objects (getSettings/getCapabilities shape) ----------
eq("plain object → recursive props", encodeValue({ a: 1, b: "x" }),
  { valueType: "object", value: { __ctor: "Object", props: { a: { valueType: "number", value: 1 }, b: { valueType: "string", value: "x" } } } });
{
  const settings = { width: 1280, height: 720, deviceId: "cam1", facingMode: "user", frameRate: 30 };
  const r = encodeValue(settings);
  ok("nested track settings preserved (not ctor+keys)",
    r.value.props.width.value === 1280 && r.value.props.deviceId.value === "cam1" && r.value.props.frameRate.value === 30);
}
{
  const deep = { level1: { level2: { level3: { leaf: "deep-value", n: 7 } } } };
  const r = encodeValue(deep);
  ok("deeply nested value preserved", r.value.props.level1.value.props.level2.value.props.level3.value.props.leaf.value === "deep-value");
}
{ const r = encodeValue(Object.create(null)); ok("null-proto object → ctor ''", r.valueType === "object" && r.value.__ctor === ""); }

// ---- cycles ---------------------------------------------------------------
{
  const o = { a: 1 }; o.self = o;
  const r = encodeValue(o);
  ok("cycle marked, not fatal", r.valueType === "object" && r.value.props.a.value === 1 && r.value.props.self.value.__cycle === true);
  let cloneOk = true; try { structuredClone(r); } catch { cloneOk = false; }
  ok("cyclic input → cloneable output", cloneOk);
}
{
  const a = []; a.push(a);
  const r = encodeValue(a);
  ok("self-referential array → cycle marker", r.valueType === "array" && r.value[0].value.__cycle === true);
}

// ---- arrays with mixed / non-primitive elements ---------------------------
eq("array of primitives → recursive", encodeValue([1, "a", true]),
  { valueType: "array", value: [{ valueType: "number", value: 1 }, { valueType: "string", value: "a" }, { valueType: "boolean", value: true }], count: 3 });
{
  const r = encodeValue([() => {}, Symbol("z"), { k: 5 }]);
  ok("function/symbol/object INSIDE array encoded (not lost)",
    r.value[0].valueType === "function" && r.value[1].valueType === "symbol" && r.value[2].value.props.k.value === 5);
  let cloneOk = true; try { structuredClone(r); } catch { cloneOk = false; }
  ok("array with fn/symbol → cloneable output", cloneOk);
}

// ---- Error, DataView, ArrayBuffer, typed arrays + content hashes ----------
{ const r = encodeValue(new TypeError("boom")); ok("Error → structured", r.valueType === "error" && r.value.name === "TypeError" && r.value.message === "boom"); }
{
  const a = encodeValue(new Uint8Array([1, 2, 3]));
  ok("Uint8Array → typedarray + fnv + sha256", a.valueType === "typedarray" && a.value.ctor === "Uint8Array" && a.value.length === 3 &&
    /^[0-9a-f]{8}$/.test(a.value.contentHash) && a.value.sha256 === nodeSha(Buffer.from([1, 2, 3])));
  const b = encodeValue(new Uint8Array([1, 2, 4]));
  ok("different bytes → different sha256", a.value.sha256 !== b.value.sha256);
}
{
  const buf = new ArrayBuffer(4); new Uint8Array(buf).set([9, 8, 7, 6]);
  const r = encodeValue(buf);
  ok("ArrayBuffer → sha256 of bytes", r.valueType === "arraybuffer" && r.value.byteLength === 4 && r.value.sha256 === nodeSha(Buffer.from([9, 8, 7, 6])));
}
{
  const dv = new DataView(new ArrayBuffer(8)); dv.setFloat64(0, 1.5);
  const r = encodeValue(dv);
  ok("DataView → typedarray view + sha256", r.valueType === "typedarray" && r.value.ctor === "DataView" && r.value.byteLength === 8 && /^[0-9a-f]{64}$/.test(r.value.sha256));
}
{
  const f = new Float32Array([1.5, -2.25]);
  const r = encodeValue(f);
  ok("Float32Array → typedarray, sha256 of raw bytes",
    r.value.ctor === "Float32Array" && r.value.byteLength === 8 && r.value.sha256 === nodeSha(Buffer.from(f.buffer, f.byteOffset, f.byteLength)));
}

// ---- oversize → blobRef (no silent truncation) ----------------------------
{
  const big = "x".repeat(20000);
  const r = encodeValue(big);
  ok("huge string → blobRef with sha256+length, no truncation-in-place",
    r.valueType === "string" && r.value.__blobRef && r.value.__blobRef.length === 20000 && r.value.__blobRef.sha256 === nodeSha(big));
}

// ---- sync SHA-256 correctness (vs node crypto) ----------------------------
ok("sha256hex('') matches node", sha256hex("") === nodeSha(""));
ok("sha256hex('abc') matches node", sha256hex("abc") === nodeSha("abc"));
ok("sha256hex(unicode) matches node", sha256hex("héllo wörld 😀") === nodeSha("héllo wörld 😀"));
ok("sha256hex(long) matches node", sha256hex("a".repeat(1000)) === nodeSha("a".repeat(1000)));
ok("sha256hex(bytes) matches node", sha256hex(new Uint8Array([0, 1, 255, 128, 64])) === nodeSha(Buffer.from([0, 1, 255, 128, 64])));

// ---- cloneability + JSON round-trip (the anti-hang guarantee) --------------
const TRICKY = [false, null, undefined, NaN, -0, 10n, Symbol("s"), "str", 3.14, [1, [2, [3]]], { a: { b: 1 } },
  Object.create(null), function g() {}, new Uint8Array([5, 6]), new ArrayBuffer(2), new DataView(new ArrayBuffer(4)),
  new TypeError("x"), (() => { const o = {}; o.c = o; return o; })(), [() => {}, Symbol("q")]];
for (const v of TRICKY) {
  const e = encodeValue(v);
  let cl = true; try { structuredClone(e); } catch { cl = false; }
  ok(`structuredClone ok: ${e.valueType}`, cl);
  let round; try { round = JSON.parse(JSON.stringify(e)); } catch { round = Symbol("err"); }
  ok(`JSON round-trip stable: ${e.valueType}`, JSON.stringify(round) === JSON.stringify(e));
}

ok("fnv1a deterministic + 8 hex", fnv1a("abc") === fnv1a("abc") && fnv1a("abc") !== fnv1a("abd") && /^[0-9a-f]{8}$/.test(fnv1a("x")));
ok("bytesHash 8 hex", /^[0-9a-f]{8}$/.test(bytesHash([1, 2, 3])));

console.log(`\nfp-encode: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
