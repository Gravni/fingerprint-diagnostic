// Regression tests for the typed-measurement schema (Codex v4 §Regression).
import { validateMeasurement, classifySessionSchema, findDuplicatePaths, classifyNetworkSchema, nonOkAllowed, scanUnexpected } from "../lib/fp-schema.mjs";

let pass = 0, fail = 0;
function ok(label, cond) { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } }
const rec = (o) => Object.assign({ path: "p", context: "main-frame", phase: "passive", status: "ok", valueType: "string", value: "", error: null, meta: {} }, o);

// valid records
ok("valid boolean", validateMeasurement(rec({ valueType: "boolean", value: false })).length === 0);
ok("valid number", validateMeasurement(rec({ valueType: "number", value: 42 })).length === 0);
ok("valid NaN", validateMeasurement(rec({ valueType: "number", value: null, meta: { special: "NaN" } })).length === 0);
ok("valid recursively encoded array", validateMeasurement(rec({ valueType: "array", value: [
  { valueType: "number", value: 1 }, { valueType: "string", value: "x" },
], meta: { count: 2 } })).length === 0);
ok("valid recursively encoded object", validateMeasurement(rec({ valueType: "object", value: {
  __ctor: "Object", props: { a: { valueType: "boolean", value: true } },
} })).length === 0);
ok("valid undefined", validateMeasurement(rec({ valueType: "undefined", value: null })).length === 0);
ok("valid error status", validateMeasurement(rec({ status: "error", valueType: null, value: null, error: { name: "TypeError", message: "x" } })).length === 0);
ok("valid unavailable", validateMeasurement(rec({ status: "unavailable-in-context", valueType: "null", value: null })).length === 0);
ok("valid symbol uses its serialized string", validateMeasurement(rec({ valueType: "symbol", value: "Symbol(x)" })).length === 0);
ok("valid function uses its serialized signature", validateMeasurement(rec({ valueType: "function", value: "foo/2" })).length === 0);

// THE key regressions — a record must not lie about its own type
ok("boolean 'false' string is REJECTED as boolean", validateMeasurement(rec({ valueType: "boolean", value: "false" })).includes("boolean-value"));
ok("array stringified is REJECTED", validateMeasurement(rec({ valueType: "array", value: "[1,2,3]" })).includes("array-not-array"));
ok("array count < length REJECTED (under-report)", validateMeasurement(rec({ valueType: "array", value: [{ valueType: "number", value: 1 }, { valueType: "number", value: 2 }, { valueType: "number", value: 3 }], meta: { count: 2 } })).includes("array-count"));
ok("array count > length OK (v4.3 cap is explicit)", validateMeasurement(rec({ valueType: "array", value: [{ valueType: "number", value: 1 }, { valueType: "number", value: 2 }], meta: { count: 9000 } })).length === 0);
ok("legacy short blobRef cannot masquerade as current evidence", validateMeasurement(rec({ valueType: "string", value: { __blobRef: { kind: "string", sha256: "a".repeat(64), fnv: "deadbeef", length: 99, preview: "x" } } })).includes("blobref-incomplete"));
ok("complete content-addressed blobRef is valid", validateMeasurement(rec({ valueType: "string", value: { __blobRef: {
  kind: "string", sha256: "a".repeat(64), addressSha256: "b".repeat(64),
  fnv: "deadbeef", addressFnv: "feedface", length: 99, preview: "x",
  reason: "string-limit", encoding: "utf-8", addressVersion: "fp-blob-address-v1",
  complete: true, hashScope: "content", lengthUnit: "utf16-code-units", stored: false,
} } })).length === 0);
ok("explicitly incomplete blobRef blocks a current capture", validateMeasurement(rec({ valueType: "string", value: { __blobRef: {
  kind: "string", sha256: "a".repeat(64), fnv: "deadbeef", length: 99, preview: "x",
  complete: false, hashScope: "marker", stored: false,
} } })).includes("blobref-incomplete"));
ok("content claim with marker hash scope is rejected", validateMeasurement(rec({ valueType: "string", value: { __blobRef: {
  kind: "string", sha256: "a".repeat(64), fnv: "deadbeef", length: 99, preview: "x",
  complete: true, hashScope: "marker", stored: false,
} } })).includes("blobref-incomplete"));
ok("cycle value OK for object", validateMeasurement(rec({ valueType: "object", value: { __cycle: true } })).length === 0);
ok("number 'NaN' string REJECTED as number", validateMeasurement(rec({ valueType: "number", value: "NaN" })).includes("number-value"));
ok("bad status enum REJECTED", validateMeasurement(rec({ status: "weird" })).some((x) => x.startsWith("status-enum")));
ok("bad valueType enum REJECTED", validateMeasurement(rec({ valueType: "blob" })).some((x) => x.startsWith("valuetype-enum")));
ok("error status with non-null value REJECTED", validateMeasurement(rec({ status: "error", value: "boom", error: { name: "E" } })).includes("error-value-not-null"));
ok("error status without error obj REJECTED", validateMeasurement(rec({ status: "error", value: null, error: null })).includes("error-missing"));
ok("non-ok status with value REJECTED", validateMeasurement(rec({ status: "blocked", value: "x" })).includes("nonok-value-not-null"));
ok("missing field REJECTED", validateMeasurement({ path: "p", context: "c", status: "ok" }).some((x) => x.startsWith("missing:")));
ok("empty phase REJECTED", validateMeasurement(rec({ phase: "" })).includes("phase"));
ok("array meta REJECTED", validateMeasurement(rec({ meta: [] })).includes("meta"));
ok("ok record carrying error REJECTED", validateMeasurement(rec({ error: { name: "E" } })).includes("unexpected-error"));
ok("symbol with non-string payload REJECTED", validateMeasurement(rec({ valueType: "symbol", value: 1 })).includes("symbol-value"));
ok("function with non-string payload REJECTED", validateMeasurement(rec({ valueType: "function", value: {} })).includes("function-value"));
ok("NaN marker with arbitrary value REJECTED", validateMeasurement(rec({ valueType: "number", value: 7, meta: { special: "NaN" } })).includes("special-value"));
ok("-0 marker requires zero payload", validateMeasurement(rec({ valueType: "number", value: 1, meta: { special: "-0" } })).includes("special-value"));
ok("array cannot masquerade as null", validateMeasurement(rec({ valueType: "array", value: null, meta: { count: 4 } })).includes("array-not-array"));
ok("malformed blobRef REJECTED", validateMeasurement(rec({ valueType: "string", value: { __blobRef: { sha256: "x", length: -1 } } })).includes("blobref"));
ok("fake cycle marker REJECTED", validateMeasurement(rec({ valueType: "object", value: { __cycle: "yes" } })).includes("cycle-marker"));
ok("error status rejects bogus valueType", validateMeasurement(rec({ status: "error", valueType: "banana", value: null, error: { name: "E" } })).includes("nonvalue-valuetype"));
ok("non-ok status rejects bogus valueType", validateMeasurement(rec({ status: "blocked", valueType: "banana", value: null })).includes("nonvalue-valuetype"));
ok("ordinary NaN requires a special marker", validateMeasurement(rec({ valueType: "number", value: NaN })).includes("nonfinite-number"));
ok("ordinary Infinity requires a special marker", validateMeasurement(rec({ valueType: "number", value: Infinity })).includes("nonfinite-number"));
ok("ordinary -0 requires a special marker", validateMeasurement(rec({ valueType: "number", value: -0 })).includes("unmarked-negative-zero"));
ok("array count must be a non-negative integer", validateMeasurement(rec({ valueType: "array", value: [], meta: { count: 1.5 } })).includes("array-count"));
ok("count metadata on a string is rejected", validateMeasurement(rec({ valueType: "string", value: "x", meta: { count: 1 } })).includes("count-nonarray"));
ok("blob kind must match encoded value type", validateMeasurement(rec({ valueType: "string", value: { __blobRef: { kind: "array", sha256: "a".repeat(64), fnv: "deadbeef", length: 1, preview: "x" } } })).includes("blobref-kind"));
ok("malformed nested array element is rejected", validateMeasurement(rec({ valueType: "array", value: [{ valueType: "boolean", value: "false" }], meta: { count: 1 } })).some((x) => x.startsWith("nested:")));
ok("malformed nested object property is rejected", validateMeasurement(rec({ valueType: "object", value: { __ctor: "Object", props: { a: { valueType: "number", value: "1" } } } })).some((x) => x.startsWith("nested:")));
ok("raw arbitrary object is not a recursively encoded object", validateMeasurement(rec({ valueType: "object", value: { a: 1 } })).includes("object-shape"));

// Hostile encoded trees must be rejected with one stable budget error before
// recursion or traversal can exhaust the process.
const nestedObject = (levels) => {
  let child = { valueType: "string", value: "leaf" };
  for (let i = 0; i < levels; i++) child = { valueType: "object", value: { __ctor: "Object", props: { child } } };
  return child;
};
{
  const hostile = nestedObject(20_000);
  let first, second, threw = false;
  try {
    first = validateMeasurement(rec({ valueType: hostile.valueType, value: hostile.value }));
    second = validateMeasurement(rec({ valueType: hostile.valueType, value: hostile.value }));
  } catch { threw = true; }
  ok("deep encoded tree never overflows the validator", !threw);
  ok("deep encoded tree has one deterministic depth-limit error",
    JSON.stringify(first) === '["encoded-limit:depth"]' && JSON.stringify(second) === JSON.stringify(first));
}
{
  const value = Array.from({ length: 8193 }, () => ({ valueType: "null", value: null }));
  ok("oversized encoded array is rejected before walking its entries",
    JSON.stringify(validateMeasurement(rec({ valueType: "array", value, meta: { count: value.length } }))) === '["encoded-limit:array-length"]');
}
{
  const props = Object.fromEntries(Array.from({ length: 513 }, (_, i) => ["k" + i, { valueType: "null", value: null }]));
  ok("oversized encoded object is rejected before walking its properties",
    JSON.stringify(validateMeasurement(rec({ valueType: "object", value: { __ctor: "Object", props } }))) === '["encoded-limit:keys"]');
}
{
  const value = Array.from({ length: 20 }, (_, group) => ({
    valueType: "object",
    value: { __ctor: "Object", props: Object.fromEntries(Array.from({ length: 512 }, (_, i) => ["k" + group + "_" + i, { valueType: "null", value: null }])) },
  }));
  ok("aggregate encoded-node budget is shared across branches",
    JSON.stringify(validateMeasurement(rec({ valueType: "array", value, meta: { count: value.length } }))) === '["encoded-limit:nodes"]');
}
{
  const hostile = nestedObject(20_000);
  let status, threw = false;
  try { status = classifySessionSchema({ _schema: "typed-v4", _measurements: [rec({ valueType: hostile.valueType, value: hostile.value })] }); }
  catch { threw = true; }
  ok("session classifier rejects a deep hostile encoded tree without throwing", !threw && status === "INVALID");
}

// session schema classification
ok("legacy flat map → LEGACY_LOSSY", classifySessionSchema({ "navigator.userAgent": "Mozilla…", _collectMs: 5 }) === "LEGACY_LOSSY");
ok("typed-v4 session → CURRENT", classifySessionSchema({ _schema: "typed-v4", _measurements: [rec({ valueType: "boolean", value: true })] }) === "CURRENT");
ok("typed records without a schema marker are not CURRENT", classifySessionSchema({ _measurements: [rec({ valueType: "boolean", value: true })] }) === "MIXED");
ok("an explicitly partial typed session is not CURRENT", classifySessionSchema({ _schema: "typed-v4-partial", _measurements: [rec({ valueType: "boolean", value: true })] }) === "MIXED");
ok("an unknown typed schema is INVALID", classifySessionSchema({ _schema: "typed-v999", _measurements: [rec({ valueType: "boolean", value: true })] }) === "INVALID");
ok("mixed session → MIXED", classifySessionSchema({ _schema: "typed-v4", _measurements: [rec({ valueType: "boolean", value: true }), rec({ valueType: "boolean", value: "nope" })] }) === "MIXED");
ok("explicit empty typed session → INVALID", classifySessionSchema({ _measurements: [] }) === "INVALID");
ok("oversized measurement array is rejected before walking every record",
  classifySessionSchema({ _schema: "typed-v4", _measurements: Array.from({ length: 8193 }, () => rec({ valueType: "null", value: null })) }) === "INVALID");
{
  const records = Array.from({ length: 20 }, (_, group) => rec({
    path: "wide." + group,
    valueType: "object",
    value: { __ctor: "Object", props: Object.fromEntries(Array.from({ length: 512 }, (_, i) => ["k" + i, { valueType: "null", value: null }])) },
  }));
  ok("session classifier shares one encoded-node budget across records",
    classifySessionSchema({ _schema: "typed-v4", _measurements: records }) === "INVALID");
}

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
ok("same path in different contexts is NOT a duplicate", findDuplicatePaths({ _measurements: [rec({ path: "screen.width", context: "main-frame" }), rec({ path: "screen.width", context: "iframe" })] }).length === 0);
{
  const d = findDuplicatePaths({ _measurements: [rec({ path: "screen.width", context: "main-frame" }), rec({ path: "screen.width", context: "main-frame" })] });
  ok("duplicate identity includes context", d.length === 1 && d[0].context === "main-frame" && d[0].path === "screen.width");
}
{
  const d = findDuplicatePaths({ _measurements: [rec({ path: "only-once-in-output" }), rec({ path: "only-once-in-output" }), rec({ path: "only-once-in-output" })] });
  ok("one duplicate key produces exactly one result entry", d.length === 1 && d[0].count === 3);
}

// ---- #3 network schema is graded SEPARATELY -------------------------------
const netFull = { ja4: "t13d…", tlsVersion: "13", httpVersion: "1.1", headerOrder: "Host,…", parserVersion: "net-v4", captureBuild: "net-v4" };
ok("legacy net-v4 record is never CURRENT", classifyNetworkSchema(netFull) === "LEGACY");
ok("partial net record → PARTIAL", classifyNetworkSchema({ ja4: "x", httpVersion: "2" }) === "PARTIAL");
ok("empty net record → MISSING", classifyNetworkSchema({}) === "MISSING");
ok("undefined net record → MISSING", classifyNetworkSchema(undefined) === "MISSING");
// a flat network record run through the BROWSER classifier is LEGACY_LOSSY — the
// exact trap #3 fixes (it must NOT be applied to network records).
ok("network record via browser classifier → LEGACY_LOSSY (why it's graded apart)", classifySessionSchema(netFull) === "LEGACY_LOSSY");
// net-v5 was typed but did not capture HTTP/2 SETTINGS or pseudo-header order.
// It remains readable historical evidence, never a CURRENT complete capture.
const netV5 = { netSchemaVersion: "net-v5", ja4: "t13d…", tlsVersion: "13", httpVersion: "2", headerOrder: "Host,Accept", parserVersion: "net-v5", captureBuild: "net-v5",
  tlsTyped: { ciphers: [4865], extensions: [0], sigAlgs: [1027], curves: [29], pointFormats: [0] }, httpHeadersTyped: [{ name: "Host", value: "x" }] };
ok("net-v5 typed record is historical, never CURRENT", classifyNetworkSchema(netV5) === "LEGACY");
ok("net-v5 missing typed arrays → PARTIAL", classifyNetworkSchema({ netSchemaVersion: "net-v5", ja4: "x", tlsVersion: "13", httpVersion: "2", parserVersion: "p", captureBuild: "b" }) === "PARTIAL");
ok("net-v5 typed but no flat fields → PARTIAL", classifyNetworkSchema({ netSchemaVersion: "net-v5", tlsTyped: netV5.tlsTyped, httpHeadersTyped: [] }) === "PARTIAL");
ok("net-v5 rejects non-numeric TLS vector entries", classifyNetworkSchema({ ...netV5, tlsTyped: { ...netV5.tlsTyped, ciphers: ["4865"] } }) === "INVALID");
ok("net-v5 rejects malformed ordered header entries", classifyNetworkSchema({ ...netV5, httpHeadersTyped: [{ name: "Host" }] }) === "INVALID");
ok("net-v5 rejects unknown schema version", classifyNetworkSchema({ ...netV5, netSchemaVersion: "net-v999" }) === "INVALID");

const netV6 = {
  netSchemaVersion: "net-v6", ja4: "t13d0207h2_62ed6f6ca7ad_032b58638d3d",
  ja3: "af851f784aed02a8b1e0b6ac13251239", ja3String: "771,4865-4866,0-10-11-13-16-43-51,29,0",
  sni: "capture.example",
  observedIp: "203.0.113.17",
  observedIpFamily: "ipv4",
  tlsTerminatedBy: "capture-endpoint",
  round: 2,
  tlsVersion: "13", httpVersion: "2.0", alpnNegotiated: "h2",
  headerOrder: ":method,:authority,:scheme,:path,user-agent,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-ch-ua-platform-version,sec-ch-ua-arch,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-full-version-list,sec-ch-ua-wow64,sec-ch-ua-form-factors", parserVersion: "net-v6",
  captureBuild: "a".repeat(64),
  captureRuntime: { node: "v22.14.0", v8: "12.4.254.21-node.22", openssl: "3.0.15", nghttp2: "1.64.0" },
  acceptChAdvertised: "platform-version,arch,bitness,model,full-version-list,wow64,form-factors",
  userAgent: "Chrome",
  secChUa: '\"Chromium\";v="140"', secChUaMobile: "?0", secChUaPlatform: '\"macOS\"',
  secChUaPlatformVersion: '\"15.6.0\"', secChUaArch: '\"arm\"', secChUaBitness: '\"64\"',
  secChUaModel: '\"\"', secChUaFullVersionList: '\"Chromium\";v="140.0.0.0"', secChUaWow64: "?0",
  secChUaFormFactors: '\"Desktop\"',
  tlsTyped: {
    tlsRecordVersion: 0x0301, handshakeVersion: 771, supportedVersionMax: 0x0304,
    ciphers: [4865, 4866], extensions: [0, 10, 11, 13, 16, 43, 51],
    sigAlgs: [1027], curves: [29], pointFormats: [0], alpnOffered: ["h2"], alpnRaw: [[104, 50]],
  },
  httpHeadersTyped: [
    { name: ":method", value: "GET", wireIndex: 0 },
    { name: ":authority", value: "capture.example", wireIndex: 1 },
    { name: ":scheme", value: "https", wireIndex: 2 },
    { name: ":path", value: "/?round=2", wireIndex: 3 },
    { name: "user-agent", value: "Chrome", wireIndex: 4 },
    { name: "sec-ch-ua", value: '\"Chromium\";v="140"', wireIndex: 5 },
    { name: "sec-ch-ua-mobile", value: "?0", wireIndex: 6 },
    { name: "sec-ch-ua-platform", value: '\"macOS\"', wireIndex: 7 },
    { name: "sec-ch-ua-platform-version", value: '\"15.6.0\"', wireIndex: 8 },
    { name: "sec-ch-ua-arch", value: '\"arm\"', wireIndex: 9 },
    { name: "sec-ch-ua-bitness", value: '\"64\"', wireIndex: 10 },
    { name: "sec-ch-ua-model", value: '\"\"', wireIndex: 11 },
    { name: "sec-ch-ua-full-version-list", value: '\"Chromium\";v="140.0.0.0"', wireIndex: 12 },
    { name: "sec-ch-ua-wow64", value: "?0", wireIndex: 13 },
    { name: "sec-ch-ua-form-factors", value: '\"Desktop\"', wireIndex: 14 },
  ],
  http2: {
    status: "captured",
    settings: [
      { id: 1, name: "headerTableSize", value: 65536, wireIndex: 0 },
      { id: 4, name: "initialWindowSize", value: 6291456, wireIndex: 1 },
    ],
    settingsOrder: [1, 4],
    settingsEffective: { headerTableSize: 65536, initialWindowSize: 6291456 },
    settingsPayloadHex: "000100010000000400600000",
    settingsPayloadSha256: "9847b1340ba7da770ff193b4f6424c65bde53fbdaa1bb7b36cd7dfe6fb3e772d",
    pseudoHeaderOrder: [":method", ":authority", ":scheme", ":path"],
    headersStatus: "valid", errors: [],
  },
};
ok("net-v6 complete HTTP/2 capture → CURRENT", classifyNetworkSchema(netV6) === "CURRENT");
ok("net-v6 priming round is never the final CURRENT record", classifyNetworkSchema({ ...netV6, round: 1 }) === "PARTIAL");
ok("net-v6 missing round cannot be relabelled final", classifyNetworkSchema((({ round: _round, ...rest }) => rest)(netV6)) === "PARTIAL");
ok("net-v6 rejects malformed round metadata", classifyNetworkSchema({ ...netV6, round: "2" }) === "INVALID");
ok("net-v6 requires negotiated h2", classifyNetworkSchema({ ...netV6, alpnNegotiated: "http/1.1" }) === "PARTIAL");
ok("net-v6 requires the observed peer IP", classifyNetworkSchema((({ observedIp: _ip, ...rest }) => rest)(netV6)) === "PARTIAL");
ok("net-v6 rejects an unknown peer address", classifyNetworkSchema({ ...netV6, observedIp: "unknown" }) === "PARTIAL");
ok("net-v6 requires peer address family consistency", classifyNetworkSchema({ ...netV6, observedIpFamily: "ipv6" }) === "PARTIAL");
ok("net-v6 accepts a socket-observed IPv4-mapped IPv6 peer", classifyNetworkSchema({
  ...netV6, observedIp: "::ffff:203.0.113.17", observedIpFamily: "ipv6",
}) === "CURRENT");
ok("net-v6 binds TLS evidence to the direct capture endpoint", classifyNetworkSchema({
  ...netV6, tlsTerminatedBy: "reverse-proxy",
}) === "PARTIAL");
ok("net-v6 requires captured initial SETTINGS", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, status: "invalid" } }) === "PARTIAL");
ok("net-v6 rejects malformed SETTINGS entries", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, settings: [{ id: "1", value: 3, wireIndex: 0 }] } }) === "INVALID");
ok("net-v6 rejects a mismatched SETTINGS order", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, settingsOrder: [4, 1] } }) === "INVALID");
ok("net-v6 rejects malformed pseudo-header order", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, pseudoHeaderOrder: [":method", "host"] } }) === "INVALID");
ok("net-v6 requires a real 256-bit executable-tree build id", classifyNetworkSchema({ ...netV6, captureBuild: "net-v6" }) === "PARTIAL");
ok("net-v6 requires capture runtime provenance", classifyNetworkSchema((({ captureRuntime: _runtime, ...rest }) => rest)(netV6)) === "PARTIAL");
ok("net-v6 requires the nghttp2 runtime version", classifyNetworkSchema({
  ...netV6, captureRuntime: { ...netV6.captureRuntime, nghttp2: "" },
}) === "PARTIAL");
ok("net-v6 rejects non-contiguous header wire indexes", classifyNetworkSchema({ ...netV6, httpHeadersTyped: netV6.httpHeadersTyped.map((h, i) => i === 2 ? { ...h, wireIndex: 9 } : h) }) === "INVALID");
ok("net-v6 rejects a JA4-shaped placeholder", classifyNetworkSchema({ ...netV6, ja4: "t13d1516h2_x_y" }) === "INVALID");
ok("net-v6 rejects a missing JA3 digest", classifyNetworkSchema((({ ja3: _ja3, ...rest }) => rest)(netV6)) === "PARTIAL");
ok("net-v6 rejects a JA3 string that disagrees with typed TLS vectors",
  classifyNetworkSchema({ ...netV6, ja3String: "771,4865,0-10-11-13-16-43-51,29,0" }) === "INVALID");
ok("net-v6 rejects a JA3 digest that disagrees with the canonical string",
  classifyNetworkSchema({ ...netV6, ja3: "0".repeat(32) }) === "INVALID");
ok("net-v6 requires the typed legacy ClientHello handshake version",
  classifyNetworkSchema({ ...netV6, tlsTyped: (({ handshakeVersion: _handshakeVersion, ...rest }) => rest)(netV6.tlsTyped) }) === "INVALID");
ok("net-v6 rejects malformed typed TLS record-version metadata",
  classifyNetworkSchema({ ...netV6, tlsTyped: { ...netV6.tlsTyped, tlsRecordVersion: "769" } }) === "INVALID");
ok("net-v6 derives the flat TLS version and JA4 prefix from typed supportedVersionMax",
  classifyNetworkSchema({ ...netV6, tlsVersion: "12", ja4: netV6.ja4.replace(/^t13/, "t12") }) === "INVALID");
ok("net-v6 rejects a tampered typed supportedVersionMax despite self-consistent flat fields",
  classifyNetworkSchema({ ...netV6, tlsTyped: { ...netV6.tlsTyped, supportedVersionMax: 0x0303 } }) === "INVALID");
ok("net-v6 rejects empty TLS vectors", classifyNetworkSchema({ ...netV6, tlsTyped: { ...netV6.tlsTyped, ciphers: [] } }) === "INVALID");
ok("net-v6 rejects ALPN text/raw disagreement", classifyNetworkSchema({ ...netV6, tlsTyped: { ...netV6.tlsTyped, alpnRaw: [[104, 51]] } }) === "INVALID");
ok("net-v6 rejects a forged SETTINGS payload digest", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, settingsPayloadSha256: "b".repeat(64) } }) === "INVALID");
ok("net-v6 rejects SETTINGS bytes that disagree with decoded entries", classifyNetworkSchema({ ...netV6, http2: { ...netV6.http2, settingsPayloadHex: "000100000001000400600000" } }) === "INVALID");
ok("net-v6 requires the normal request pseudo-header set", classifyNetworkSchema({
  ...netV6,
  headerOrder: ":method,user-agent",
  httpHeadersTyped: [netV6.httpHeadersTyped[0], { name: "user-agent", value: "Chrome", wireIndex: 1 }],
  http2: { ...netV6.http2, pseudoHeaderOrder: [":method"] },
}) === "INVALID");
ok("net-v6 requires an observed user-agent header", classifyNetworkSchema({
  ...netV6,
  headerOrder: netV6.headerOrder.replace(",user-agent", ""),
  httpHeadersTyped: netV6.httpHeadersTyped.slice(0, 4),
}) === "INVALID");
{
  const headers = netV6.httpHeadersTyped.filter((h) => h.name !== "sec-ch-ua-arch").map((h, wireIndex) => ({ ...h, wireIndex }));
  ok("net-v6 requires all delegated round-2 high-entropy Client Hints",
    classifyNetworkSchema({ ...netV6, secChUaArch: "absent", headerOrder: headers.map((h) => h.name).join(","), httpHeadersTyped: headers }) === "PARTIAL");
}
ok("net-v6 rejects a flat user-agent that disagrees with the typed header",
  classifyNetworkSchema({ ...netV6, userAgent: "Forged browser" }) === "INVALID");
ok("net-v6 rejects a flat UA-CH value that disagrees with the typed header",
  classifyNetworkSchema({ ...netV6, secChUaArch: '\"x86\"' }) === "INVALID");
ok("net-v6 rejects flat 'absent' when the corresponding typed UA-CH header exists",
  classifyNetworkSchema({ ...netV6, secChUaWow64: "absent" }) === "INVALID");
{
  const emptyFlat = {
    secChUa: "", secChUaMobile: "", secChUaPlatform: "", secChUaPlatformVersion: "",
    secChUaArch: "", secChUaBitness: "", secChUaModel: "", secChUaFullVersionList: "", secChUaWow64: "",
    secChUaFormFactors: "",
  };
  const headers = netV6.httpHeadersTyped.map((h) => h.name.startsWith("sec-ch-ua") ? { ...h, value: "" } : h);
  ok("net-v6 matching but empty UA-CH fields are not CURRENT",
    classifyNetworkSchema({ ...netV6, ...emptyFlat, httpHeadersTyped: headers }) === "PARTIAL");
}
{
  const headers = netV6.httpHeadersTyped.map((h) => h.name === "sec-ch-ua-mobile" ? { ...h, value: "false" } : h);
  ok("net-v6 requires structured-boolean syntax for UA-CH booleans",
    classifyNetworkSchema({ ...netV6, secChUaMobile: "false", httpHeadersTyped: headers }) === "PARTIAL");
}
{
  const headers = netV6.httpHeadersTyped.map((h) => h.name === "sec-ch-ua-platform" ? { ...h, value: "macOS" } : h);
  ok("net-v6 requires structured-string syntax for quoted UA-CH values",
    classifyNetworkSchema({ ...netV6, secChUaPlatform: "macOS", httpHeadersTyped: headers }) === "PARTIAL");
}
{
  const headers = netV6.httpHeadersTyped.map((h) => h.name === "sec-ch-ua-form-factors"
    ? { ...h, value: "Desktop" } : h);
  ok("net-v6 requires a structured string-list for form factors",
    classifyNetworkSchema({ ...netV6, secChUaFormFactors: "Desktop", httpHeadersTyped: headers }) === "PARTIAL");
}
ok("net-v6 treats matching flat/header absence as partial rather than contradictory",
  classifyNetworkSchema({
    ...netV6,
    secChUaWow64: "absent",
    headerOrder: netV6.headerOrder.replace(",sec-ch-ua-wow64", ""),
    httpHeadersTyped: netV6.httpHeadersTyped.filter((header) => header.name !== "sec-ch-ua-wow64")
      .map((header, wireIndex) => ({ ...header, wireIndex })),
  }) === "PARTIAL");
ok("net-v6 rejects a SETTINGS id/name contradiction", classifyNetworkSchema({
  ...netV6,
  http2: { ...netV6.http2, settings: netV6.http2.settings.map((s, i) => i ? s : { ...s, name: "bogusName" }) },
}) === "INVALID");
ok("net-v6 rejects invalid enablePush values", classifyNetworkSchema({
  ...netV6,
  http2: {
    ...netV6.http2,
    settings: [{ id: 2, name: "enablePush", value: 2, wireIndex: 0 }],
    settingsOrder: [2], settingsEffective: { enablePush: 2 },
    settingsPayloadHex: "000200000002",
    settingsPayloadSha256: "2e81cc35988de4bdb589e1e3f175c20704d9aefdd11cd3fc728501d06edc6b23",
  },
}) === "INVALID");

// ---- diagnostic fixture (real session) ------------------------------------
{
  const dpath = join(here, "../tests/fixtures/diagnostic-20260903-160918");
  const browser = JSON.parse(readFileSync(join(dpath, "plain.jsonl"), "utf8").trim().split("\n")[0]).measurements; // main-frame
  const net = JSON.parse(readFileSync(join(dpath, "plain.net.jsonl"), "utf8").trim().split("\n")[0]).measurements;
  ok("pre-v4.3 fixture main-frame exposes mixed nested encoding", classifySessionSchema(browser) === "MIXED");
  ok("legacy fixture network schema → LEGACY", classifyNetworkSchema(net) === "LEGACY");
  ok("fixture main-frame has the known uach duplicates", findDuplicatePaths(browser).some((d) => d.path === "uach.brands"));
}

// ---- #2 enumerated allowed non-ok + unexpected scan -----------------------
ok("ok is always allowed", nonOkAllowed("anything", "main-frame", "ok"));
ok("webgpu blocked allowed anywhere", nonOkAllowed("webgpu.status", "main-frame", "blocked"));
for (const path of [
  "webgpu.isFallback", "webgpu.vendor", "webgpu.architecture", "webgpu.device",
  "webgpu.description", "webgpu.wgslFeatures", "webgpu.preferredFormat",
]) {
  ok(`${path} may be explicitly unavailable when the optional WebGPU property is absent`,
    nonOkAllowed(path, "main-frame", "unavailable-in-context"));
}
ok("WebGPU optional-metadata allowlist is exact, not a family wildcard",
  !nonOkAllowed("webgpu.vendor.extra", "main-frame", "unavailable-in-context")
    && !nonOkAllowed("webgpu.limits.maxTextureDimension2D", "main-frame", "unavailable-in-context"));
ok("WebGPU optional metadata cannot hide a blocked or errored probe",
  !nonOkAllowed("webgpu.vendor", "main-frame", "blocked")
    && !nonOkAllowed("webgpu.vendor", "main-frame", "error"));
for (const context of [
  "dedicated-worker", "dedicated-worker-module", "shared-worker",
  "shared-worker-module", "service-worker", "audio-worklet",
]) {
  ok(`realtime AudioContext absence is explicit in ${context}`,
    nonOkAllowed("audio.realtime.available", context, "unavailable-in-context"));
}
ok("realtime AudioContext absence is not excused in a window realm",
  !nonOkAllowed("audio.realtime.available", "main-frame", "unavailable-in-context"));
ok("realtime audio allowlist covers only the availability marker",
  !nonOkAllowed("audio.realtime.sampleRate", "dedicated-worker", "unavailable-in-context")
    && !nonOkAllowed("audio.realtime.available", "dedicated-worker", "error"));
ok("permissioned denied is not READY-allowlisted", !nonOkAllowed("permissioned.geo", "permissioned", "permission-denied"));
ok("canvas status unavailable allowed in a worker", nonOkAllowed("canvas.status", "dedicated-worker", "unavailable-in-context"));
ok("UNEXPECTED: dotted navigator path in worker is NOT document-only", !nonOkAllowed("navigator.userAgent", "dedicated-worker", "unavailable-in-context"));
ok("UNEXPECTED: arbitrary error in cross-origin frame is NOT allowlisted", !nonOkAllowed("navigator.userAgent", "cross-origin-iframe", "error"));
ok("UNEXPECTED: arbitrary blocked value in sandbox is NOT allowlisted", !nonOkAllowed("screen.width", "sandboxed-iframe", "blocked"));
ok("opaque sandbox localStorage denial is an exact expected capability outcome",
  nonOkAllowed("storage.localStorage", "sandboxed-iframe", "blocked"));
ok("opaque sandbox sessionStorage denial is an exact expected capability outcome",
  nonOkAllowed("storage.sessionStorage", "sandboxed-iframe", "blocked"));
ok("opaque sandbox CacheStorage denial is an exact expected capability outcome",
  nonOkAllowed("storage.caches", "sandboxed-iframe", "blocked"));
ok("opaque sandbox serviceWorker denial is an exact expected capability outcome",
  nonOkAllowed("navigator.serviceWorker", "sandboxed-iframe", "blocked"));
ok("opaque sandbox keyboard policy denial is an exact expected capability outcome",
  nonOkAllowed("keyboard.available", "sandboxed-iframe", "blocked"));
ok("sandbox does not blanket-allow other blocked storage probes",
  !nonOkAllowed("storage.indexedDB", "sandboxed-iframe", "blocked"));
ok("cross-origin iframe keyboard denial is not excused by sandbox rules",
  !nonOkAllowed("keyboard.available", "cross-origin-iframe", "blocked"));
ok("UNEXPECTED: permission denial blocks a one-shot complete capture", !nonOkAllowed("permissioned.geo", "permissioned", "permission-denied"));
ok("UNEXPECTED: permission timeout blocks a one-shot complete capture", !nonOkAllowed("permissioned.getUserMedia", "permissioned", "timeout"));
ok("UNEXPECTED: invalid device result is not an allowed capability absence", !nonOkAllowed("device.battery", "main-frame", "invalid-result"));
ok("UNEXPECTED: realtime audio error is not silently accepted", !nonOkAllowed("audio.realtime.hash", "main-frame", "error"));
ok("UNEXPECTED: WebRTC leaf cannot hide behind feature-family allowlist", !nonOkAllowed("webrtc.codecs", "main-frame", "blocked"));
ok("UNEXPECTED: MediaDevices error leaf cannot be marked unsupported", !nonOkAllowed("mediaDevices.error", "main-frame", "unsupported"));
ok("UNEXPECTED: storage error is not a capability status", !nonOkAllowed("storage.error", "main-frame", "unavailable-in-context"));
ok("UNEXPECTED: codec DOM result unavailable in main frame", !nonOkAllowed("codecs.canPlay[video/mp4]", "main-frame", "unavailable-in-context"));
ok("codec DOM result unavailable in a real worker is allowed", nonOkAllowed("codecs.canPlay[video/mp4]", "dedicated-worker", "unavailable-in-context"));
ok("emitted MSE path unavailable in a service worker is allowed", nonOkAllowed("codecs.mse[video/mp4]", "service-worker", "unavailable-in-context"));
ok("visualViewport leaves remain explicit when the realm has no viewport",
  nonOkAllowed("env.vvScale", "dedicated-worker", "unavailable-in-context")
    && nonOkAllowed("env.vvWidth", "main-frame", "unavailable-in-context"));
ok("obsolete mediaSource alias is not accidentally allowlisted", !nonOkAllowed("codecs.mediaSource[video/mp4]", "service-worker", "unavailable-in-context"));
ok("context name containing worker is not automatically a worker realm", !nonOkAllowed("canvas.status", "not-a-worker-proxy", "unavailable-in-context"));
ok("audio-worklet navigator absence is explicitly allowed", nonOkAllowed("navigator.userAgent", "audio-worklet", "unavailable-in-context"));
ok("control engine failure is never capability-optional", !nonOkAllowed("control.thumbmark.hash", "main-frame", "blocked"));
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
{
  const sess = { _measurements: [
    rec({ path: "canvas.hash", context: "main-frame", status: "unavailable-in-context", valueType: "null", value: null }),
  ] };
  const u = scanUnexpected(sess, "dedicated-worker");
  ok("scanUnexpected rejects a record whose embedded context disagrees", u.length === 1 && u[0].status === "context-mismatch");
}

console.log(`\nfp-schema: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
