// Regression tests for the typed-measurement schema (Codex v4 §Regression).
import { validateMeasurement, classifySessionSchema, findDuplicatePaths, classifyNetworkSchema, nonOkAllowed, scanUnexpected } from "../lib/fp-schema.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }
const rec = (o) => Object.assign({ path: "p", context: "main-frame", phase: "passive", status: "ok", valueType: "string", value: "", error: null, meta: {} }, o);

// valid records
ok("valid boolean", validateMeasurement(rec({ valueType: "boolean", value: false })).length === 0);
ok("valid number", validateMeasurement(rec({ valueType: "number", value: 42 })).length === 0);
ok("valid NaN", validateMeasurement(rec({ valueType: "number", value: null, meta: { special: "NaN" } })).length === 0);
ok("valid array count", validateMeasurement(rec({ valueType: "array", value: [1, 2, 3], meta: { count: 3 } })).length === 0);
ok("valid undefined", validateMeasurement(rec({ valueType: "undefined", value: null })).length === 0);
ok("valid error status", validateMeasurement(rec({ status: "error", valueType: null, value: null, error: { name: "TypeError", message: "x" } })).length === 0);
ok("valid unavailable", validateMeasurement(rec({ status: "unavailable-in-context", valueType: "null", value: null })).length === 0);

// THE key regressions — a record must not lie about its own type
ok("boolean 'false' string is REJECTED as boolean", validateMeasurement(rec({ valueType: "boolean", value: "false" })).includes("boolean-value"));
ok("array stringified is REJECTED", validateMeasurement(rec({ valueType: "array", value: "[1,2,3]" })).includes("array-not-array"));
ok("array count < length REJECTED (under-report)", validateMeasurement(rec({ valueType: "array", value: [1, 2, 3], meta: { count: 2 } })).includes("array-count"));
ok("array count > length OK (v4.3 truncation: count=orig, value capped)", validateMeasurement(rec({ valueType: "array", value: [1, 2], meta: { count: 9000 } })).length === 0);
ok("blobRef value OK for string", validateMeasurement(rec({ valueType: "string", value: { __blobRef: { sha256: "x", length: 99 } } })).length === 0);
ok("cycle value OK for object", validateMeasurement(rec({ valueType: "object", value: { __cycle: true } })).length === 0);
ok("number 'NaN' string REJECTED as number", validateMeasurement(rec({ valueType: "number", value: "NaN" })).includes("number-value"));
ok("bad status enum REJECTED", validateMeasurement(rec({ status: "weird" })).some((x) => x.startsWith("status-enum")));
ok("bad valueType enum REJECTED", validateMeasurement(rec({ valueType: "blob" })).some((x) => x.startsWith("valuetype-enum")));
ok("error status with non-null value REJECTED", validateMeasurement(rec({ status: "error", value: "boom", error: { name: "E" } })).includes("error-value-not-null"));
ok("error status without error obj REJECTED", validateMeasurement(rec({ status: "error", value: null, error: null })).includes("error-missing"));
ok("non-ok status with value REJECTED", validateMeasurement(rec({ status: "blocked", value: "x" })).includes("nonok-value-not-null"));
ok("missing field REJECTED", validateMeasurement({ path: "p", context: "c", status: "ok" }).some((x) => x.startsWith("missing:")));

// session schema classification
ok("legacy flat map → LEGACY_LOSSY", classifySessionSchema({ "navigator.userAgent": "Mozilla…", _collectMs: 5 }) === "LEGACY_LOSSY");
ok("typed session → CURRENT", classifySessionSchema({ _measurements: [rec({ valueType: "boolean", value: true })] }) === "CURRENT");
ok("mixed session → MIXED", classifySessionSchema({ _measurements: [rec({ valueType: "boolean", value: true }), rec({ valueType: "boolean", value: "nope" })] }) === "MIXED");

// The real legacy session (20260901) must classify LEGACY_LOSSY — Codex keeps it
// as a regression fixture, never as proof of v4 features.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const here = dirname(fileURLToPath(import.meta.url));
const legacy = JSON.parse(readFileSync(join(here, "../tests/fixtures/legacy-incomplete-20260901/plain.sample.json"), "utf8"));
ok("legacy fixture → LEGACY_LOSSY", classifySessionSchema(legacy) === "LEGACY_LOSSY");

// ---- #7 duplicate {context,path} detection --------------------------------
ok("no duplicates → []", findDuplicatePaths({ _measurements: [rec({ path: "a" }), rec({ path: "b" })] }).length === 0);
{
  const d = findDuplicatePaths({ _measurements: [rec({ path: "uach.brands" }), rec({ path: "uach.brands" }), rec({ path: "uach.mobile" }), rec({ path: "uach.mobile" }), rec({ path: "x" })] });
  ok("duplicates found", d.length === 2 && d[0].count === 2);
  ok("duplicate names correct", d.map((x) => x.path).sort().join(",") === "uach.brands,uach.mobile");
}
ok("non-array _measurements → no dups", findDuplicatePaths({ foo: 1 }).length === 0);

// ---- #3 network schema is graded SEPARATELY -------------------------------
const netFull = { ja4: "t13d…", tlsVersion: "13", httpVersion: "1.1", headerOrder: "Host,…", parserVersion: "net-v4", captureBuild: "net-v4" };
ok("full net record → CURRENT", classifyNetworkSchema(netFull) === "CURRENT");
ok("partial net record → PARTIAL", classifyNetworkSchema({ ja4: "x", httpVersion: "2" }) === "PARTIAL");
ok("empty net record → MISSING", classifyNetworkSchema({}) === "MISSING");
ok("undefined net record → MISSING", classifyNetworkSchema(undefined) === "MISSING");
// a flat network record run through the BROWSER classifier is LEGACY_LOSSY — the
// exact trap #3 fixes (it must NOT be applied to network records).
ok("network record via browser classifier → LEGACY_LOSSY (why it's graded apart)", classifySessionSchema(netFull) === "LEGACY_LOSSY");
// net-v5 VERSIONED typed schema (Codex v4.3 #8)
const netV5 = { netSchemaVersion: "net-v5", ja4: "t13d…", tlsVersion: "13", httpVersion: "2", parserVersion: "net-v5", captureBuild: "net-v5",
  tlsTyped: { ciphers: [4865], extensions: [0], sigAlgs: [1027], curves: [29], pointFormats: [0] }, httpHeadersTyped: [{ name: "Host", value: "x" }] };
ok("net-v5 typed record → CURRENT", classifyNetworkSchema(netV5) === "CURRENT");
ok("net-v5 missing typed arrays → PARTIAL", classifyNetworkSchema({ netSchemaVersion: "net-v5", ja4: "x", tlsVersion: "13", httpVersion: "2", parserVersion: "p", captureBuild: "b" }) === "PARTIAL");
ok("net-v5 typed but no flat fields → PARTIAL", classifyNetworkSchema({ netSchemaVersion: "net-v5", tlsTyped: netV5.tlsTyped, httpHeadersTyped: [] }) === "PARTIAL");

// ---- diagnostic fixture (real session) ------------------------------------
{
  const dpath = join(here, "../tests/fixtures/diagnostic-20260903-160918");
  const browser = JSON.parse(readFileSync(join(dpath, "plain.jsonl"), "utf8").trim().split("\n")[0]).measurements; // main-frame
  const net = JSON.parse(readFileSync(join(dpath, "plain.net.jsonl"), "utf8").trim().split("\n")[0]).measurements;
  ok("fixture main-frame browser schema → CURRENT", classifySessionSchema(browser) === "CURRENT");
  ok("fixture network schema → CURRENT", classifyNetworkSchema(net) === "CURRENT");
  ok("fixture main-frame has the known uach duplicates", findDuplicatePaths(browser).some((d) => d.path === "uach.brands"));
}

// ---- #2 enumerated allowed non-ok + unexpected scan -----------------------
ok("ok is always allowed", nonOkAllowed("anything", "main-frame", "ok"));
ok("webgpu blocked allowed anywhere", nonOkAllowed("webgpu.status", "main-frame", "blocked"));
ok("permissioned denied allowed", nonOkAllowed("permissioned.geo", "permissioned", "permission-denied"));
ok("canvas unavailable allowed in a worker", nonOkAllowed("canvas.hash", "dedicated-worker", "unavailable-in-context"));
ok("blocked allowed in sandboxed realm (SecurityError)", nonOkAllowed("navigator.userAgent", "sandboxed-iframe", "blocked"));
ok("UNEXPECTED: navigator error in main-frame NOT allowed", !nonOkAllowed("navigator.userAgent", "main-frame", "error"));
ok("UNEXPECTED: canvas error in main-frame NOT allowed", !nonOkAllowed("canvas.hash", "main-frame", "error"));
ok("UNEXPECTED: core timeout in main-frame NOT allowed", !nonOkAllowed("screen.width", "main-frame", "timeout"));
{
  const sess = { _measurements: [
    rec({ path: "webgpu.status", context: "main-frame", status: "blocked", valueType: "null", value: null }),
    rec({ path: "navigator.userAgent", context: "main-frame", status: "error", valueType: null, value: null, error: { name: "E" } }),
    rec({ path: "canvas.hash", context: "main-frame", status: "ok", valueType: "string", value: "h" }),
  ] };
  const u = scanUnexpected(sess, "main-frame");
  ok("scanUnexpected flags the navigator error only", u.length === 1 && u[0].path === "navigator.userAgent");
}

console.log(`\nfp-schema: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
