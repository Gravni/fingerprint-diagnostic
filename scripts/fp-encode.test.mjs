// Regression test for the PRODUCTION typed-value encoder (lib/fp-encode.mjs) —
// the ONE source the browser collector also runs. The encoder is deliberately
// bounded: anything not kept inline must become an explicit content-addressed
// reference, never an invisible truncation.

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

// ---- inline nested objects (getSettings/getCapabilities shape) ------------
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
{
  const source = Object.create(null);
  Object.defineProperty(source, "__proto__", { value: "kept", enumerable: true });
  source.constructor = "also-kept";
  const props = encodeValue(source).value.props;
  ok("reserved object keys are data, not prototype mutation",
    Object.prototype.hasOwnProperty.call(props, "__proto__") && props.__proto__.value === "kept" &&
    Object.prototype.hasOwnProperty.call(props, "constructor") && props.constructor.value === "also-kept");
}

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
  const sparse = []; sparse.length = 1;
  const hole = encodeValue(sparse).value[0];
  const undef = encodeValue([undefined]).value[0];
  ok("array holes stay distinguishable from explicit undefined",
    hole.valueType === "undefined" && hole.hole === true && undef.hole !== true);
}
{
  const r = encodeValue([() => {}, Symbol("z"), { k: 5 }]);
  ok("function/symbol/object INSIDE array encoded (not lost)",
    r.value[0].valueType === "function" && r.value[1].valueType === "symbol" && r.value[2].value.props.k.value === 5);
  let cloneOk = true; try { structuredClone(r); } catch { cloneOk = false; }
  ok("array with fn/symbol → cloneable output", cloneOk);
}
{
  const withExtra = [1]; withExtra.label = "observable";
  const r = encodeValue(withExtra);
  ok("enumerable non-index array properties are never silently dropped",
    !!(r.value.__blobRef && r.value.__blobRef.reason === "array-extra-properties"));
}

// ---- Error, DataView, ArrayBuffer, typed arrays + content hashes ----------
{ const r = encodeValue(new TypeError("boom")); ok("Error → structured", r.valueType === "error" && r.value.name === "TypeError" && r.value.message === "boom"); }
{
  const weird = new Error("x");
  Object.defineProperty(weird, "name", { value: 1n, enumerable: true });
  Object.defineProperty(weird, "message", { value: Symbol("message"), enumerable: true });
  Object.defineProperty(weird, "stack", { get() { throw new RangeError("stack blocked"); }, enumerable: true });
  let r, threw = false, jsonOk = true;
  try { r = encodeValue(weird); } catch { threw = true; }
  try { JSON.stringify(r); structuredClone(r); } catch { jsonOk = false; }
  ok("hostile Error fields stay typed, bounded, JSON/clone-safe",
    !threw && jsonOk && typeof r.value.name === "string" && typeof r.value.message === "string" &&
    r.value.fieldErrors && r.value.fieldErrors.stack === "RangeError: stack blocked");
}
{
  const thrown = { name: "N".repeat(300000), message: "M".repeat(300000) };
  const error = new Error("hostile thrown value");
  Object.defineProperty(error, "stack", { get() { throw thrown; } });
  const r = encodeValue(error);
  ok("hostile thrown descriptions are bounded and visibly marked",
    JSON.stringify(r).length < 10000 && /"complete":false/.test(r.value.fieldErrors.stack));
}
{
  const hostile = new Proxy(function target(a) {}, {
    get(fn, key, recv) {
      if (key === "name" || key === "length") throw new TypeError(`${String(key)} blocked`);
      return Reflect.get(fn, key, recv);
    },
  });
  let r, threw = false;
  try { r = encodeValue(hostile); } catch { threw = true; }
  ok("hostile function metadata becomes an explicit safe signature",
    !threw && r.valueType === "function" && /name-error:TypeError/.test(r.value) && /length-error:TypeError/.test(r.value));
}
{
  const hugeName = "f".repeat(1100000);
  const hostile = new Proxy(function target() {}, { get(fn, key, recv) { return key === "name" ? hugeName : Reflect.get(fn, key, recv); } });
  const r = encodeValue(hostile);
  ok("huge function metadata is bounded with an explicit ref",
    r.value.length < 512 && /function-signature-limit/.test(r.value) && /"complete":false/.test(r.value) &&
    r.signatureRef && r.signatureRef.complete === false);
}
{
  const error = new Error("huge stack");
  Object.defineProperty(error, "stack", { value: "s".repeat(1100000) });
  const r = encodeValue(error);
  ok("huge Error stack is bounded with an explicit incomplete ref",
    r.value.stack.length < 128 && r.value.stackRef && r.value.stackRef.complete === false &&
    r.value.stackRef.reason === "error-stack-limit");
}
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
{
  const detached = new ArrayBuffer(8);
  structuredClone(detached, { transfer: [detached] });
  let r, threw = false;
  try { r = encodeValue(detached); } catch { threw = true; }
  ok("detached ArrayBuffer becomes an explicit error ref",
    !threw && r.valueType === "object" && r.value.__blobRef &&
    r.value.__blobRef.originalValueType === "arraybuffer" && r.value.__blobRef.complete === false);
}
{
  const bytes = new Uint8Array(8);
  Object.defineProperty(bytes, "constructor", { get() { throw new TypeError("ctor blocked"); } });
  let r, threw = false;
  try { r = encodeValue(bytes); } catch { threw = true; }
  ok("typed-array metadata getter cannot crash encoding",
    !threw && r.valueType === "typedarray" && /constructor-error:TypeError/.test(r.value.ctor));
}
{
  const huge = new Uint8Array(1100000);
  const r = encodeValue(huge);
  ok("large binary input obeys byte budget",
    r.valueType === "object" && r.value.__blobRef && r.value.__blobRef.complete === false &&
    r.value.__blobRef.originalValueType === "typedarray");
}

// ---- oversize → blobRef (no silent truncation) ----------------------------
{
  const big = "x".repeat(20000);
  const r = encodeValue(big);
  ok("huge string → blobRef with sha256+length, no truncation-in-place",
    r.valueType === "string" && r.value.__blobRef && r.value.__blobRef.length === 20000 &&
    r.value.__blobRef.sha256 === nodeSha(big) && r.value.__blobRef.reason === "string-limit" &&
    r.value.__blobRef.complete === true && r.value.__blobRef.lengthUnit === "utf16-code-units");
}
{
  const blobs = [];
  const big = "payload-" + "x".repeat(20000);
  const r = encodeValue(big, { blobSink(blob) { blobs.push(blob); return "blob://stored/1"; } });
  ok("blobSink receives the complete exact long-string payload",
    blobs.length === 1 && blobs[0].payload === big && blobs[0].sha256 === nodeSha(big) &&
    blobs[0].reason === "string-limit" && r.value.__blobRef.locator === "blob://stored/1" &&
    r.value.__blobRef.stored === true);
}
{
  let deep = ["deep-tail"];
  for (let i = 0; i < 8; i++) deep = [deep];
  const r = encodeValue(deep);
  let cursor = r;
  for (let i = 0; i < 8; i++) cursor = cursor.value[0];
  ok("array at max depth is an explicit ref, never null",
    cursor.valueType === "array" && cursor.value !== null && cursor.value.__blobRef &&
    cursor.value.__blobRef.reason === "max-depth" && cursor.value.__blobRef.kind === "array");
}
{
  const makeDeep = (tail) => {
    let v = { tail };
    for (let i = 0; i < 8; i++) v = { child: v };
    return v;
  };
  const a = encodeValue(makeDeep("a"));
  const b = encodeValue(makeDeep("b"));
  let ar = a, br = b;
  for (let i = 0; i < 8; i++) { ar = ar.value.props.child; br = br.value.props.child; }
  ok("max-depth ref hashes the complete omitted subtree",
    !!(ar.value && br.value && ar.value.__blobRef && br.value.__blobRef &&
    ar.value.__blobRef.complete === true && ar.value.__blobRef.sha256 !== br.value.__blobRef.sha256));
}
{
  const a = Array.from({ length: 8193 }, (_, i) => i);
  const b = a.slice(); b[b.length - 1] = 999999;
  const ae = encodeValue(a), be = encodeValue(b);
  ok("array cap is an explicit full-array content ref",
    !!(ae.value && be.value && ae.value.__blobRef && be.value.__blobRef && ae.valueType === "array" &&
    ae.count === a.length && ae.value.__blobRef.reason === "array-limit" &&
    ae.value.__blobRef.complete === true && ae.value.__blobRef.lengthUnit === "elements" &&
    ae.value.__blobRef.sha256 !== be.value.__blobRef.sha256));
}
{
  const a = {}, b = {};
  for (let i = 0; i < 513; i++) { a[`k${i}`] = i; b[`k${i}`] = i; }
  b.k512 = 999999;
  const ae = encodeValue(a), be = encodeValue(b);
  ok("object key cap is an explicit full-object content ref",
    !!(ae.value && be.value && ae.value.__blobRef && be.value.__blobRef && ae.valueType === "object" &&
    ae.value.__blobRef.reason === "object-key-limit" && ae.value.__blobRef.complete === true &&
    ae.value.__blobRef.lengthUnit === "own-enumerable-keys" &&
    ae.value.__blobRef.sha256 !== be.value.__blobRef.sha256));
}
{
  const source = {};
  const key = Symbol("visible");
  Object.defineProperty(source, key, { value: 7, enumerable: true });
  const r = encodeValue(source);
  ok("enumerable symbol keys are never silently dropped",
    !!(r.value.__blobRef && r.value.__blobRef.reason === "object-symbol-keys" && r.value.__blobRef.complete === true));
}
{
  const hostile = new Proxy({}, { ownKeys() { throw new TypeError("ownKeys blocked"); } });
  let r, threw = false;
  try { r = encodeValue(hostile); } catch { threw = true; }
  ok("Object.keys failure is explicit, not a fake empty object",
    !threw && r.value.__blobRef && r.value.__blobRef.reason === "object-keys-error" && r.value.__blobRef.complete === false);
}
{
  const sparse = [];
  sparse.length = 200000;
  sparse[199999] = "tail";
  const r = encodeValue(sparse);
  ok("large sparse array cannot bypass canonical operation budget",
    r.value.__blobRef && r.value.__blobRef.reason === "array-limit" && r.value.__blobRef.complete === false);
}
{
  const fakeLength = new Proxy([], { get(target, key, recv) { return key === "length" ? 1.5 : Reflect.get(target, key, recv); } });
  const r = encodeValue(fakeLength);
  ok("invalid proxied array length is a valid explicit marker",
    r.count === 0 && r.value.__blobRef && r.value.__blobRef.reason === "array-length-error" && r.value.__blobRef.complete === false);
}
{
  const wide = Array.from({ length: 2000 }, () => "x".repeat(10000));
  const r = encodeValue(wide);
  ok("whole traversal has a shared budget and degrades explicitly",
    r.value.__blobRef && r.value.__blobRef.reason === "total-inline-budget" &&
    r.value.__blobRef.complete === false && r.value.__blobRef.hashScope === "marker");
}
{
  let deep = { tail: true };
  for (let i = 0; i < 60000; i++) deep = { child: deep };
  let r = null, threw = false;
  try { r = encodeValue(deep); } catch { threw = true; }
  let cursor = r;
  for (let i = 0; !threw && i < 8; i++) cursor = cursor.value.props.child;
  ok("pathological depth degrades to an explicit incomplete marker, not a crash",
    !threw && cursor.value.__blobRef && cursor.value.__blobRef.complete === false &&
    cursor.value.__blobRef.hashScope === "marker");
}

// ---- sync SHA-256 correctness (vs node crypto) ----------------------------
ok("sha256hex('') matches node", sha256hex("") === nodeSha(""));
ok("sha256hex('abc') matches node", sha256hex("abc") === nodeSha("abc"));
ok("sha256hex(unicode) matches node", sha256hex("héllo wörld 😀") === nodeSha("héllo wörld 😀"));
ok("sha256hex(lone high surrogate) follows WHATWG TextEncoder replacement",
  sha256hex("a\ud800b") === nodeSha("a\ud800b"));
ok("sha256hex(lone low surrogate) follows WHATWG TextEncoder replacement",
  sha256hex("a\udc00b") === nodeSha("a\udc00b"));
ok("sha256hex(high surrogate before non-low) follows WHATWG replacement",
  sha256hex("\ud800x") === nodeSha("\ud800x"));
{
  const lone = encodeValue("\ud800".repeat(17000)).value.__blobRef;
  const replacement = encodeValue("\ufffd".repeat(17000)).value.__blobRef;
  ok("blob identity distinguishes lone surrogate from U+FFFD despite WHATWG UTF-8",
    lone.addressSha256 !== replacement.addressSha256 && lone.encoding === "json-string-v1" && replacement.encoding === "utf-8");
}
{
  const ill = "\ud800".repeat(17000);
  const a = encodeValue(ill).value.__blobRef;
  const b = encodeValue(JSON.stringify(ill)).value.__blobRef;
  ok("blob address is domain-separated across payload encodings",
    a.sha256 === b.sha256 && a.addressSha256 !== b.addressSha256);
}
{
  const huge = Symbol("x".repeat(300000));
  const r = encodeValue(huge);
  ok("huge symbol description is bounded with original type recorded",
    JSON.stringify(r).length < 2000 && r.valueType === "object" &&
    r.value.__blobRef.originalValueType === "symbol" && r.value.__blobRef.complete === false);
}
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

// Cycle markers include the exact ancestor path. `__cycle:true` remains for
// schema/backward compatibility; cycleRef removes ambiguity for graphs with
// more than one possible ancestor.
{
  const root = { branch: { leaf: null } };
  root.branch.leaf = root;
  const r = encodeValue(root);
  eq("cycle reference identifies the root ancestor",
    r.value.props.branch.value.props.leaf.cycleRef, "#");
}
{
  const root = { branch: {} };
  root.branch.self = root.branch;
  const r = encodeValue(root);
  eq("cycle reference identifies a nested ancestor",
    r.value.props.branch.value.props.self.cycleRef, "#/branch");
}

{
  const encoded = [encodeValue(NaN), encodeValue(Infinity), encodeValue(-Infinity), encodeValue(-0)];
  ok("all special numbers remain pairwise unambiguous",
    new Set(encoded.map((v) => JSON.stringify(v))).size === encoded.length);
}

ok("fnv1a deterministic + 8 hex", fnv1a("abc") === fnv1a("abc") && fnv1a("abc") !== fnv1a("abd") && /^[0-9a-f]{8}$/.test(fnv1a("x")));
ok("bytesHash 8 hex", /^[0-9a-f]{8}$/.test(bytesHash([1, 2, 3])));

console.log(`\nfp-encode: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
