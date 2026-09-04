import { readFileSync } from "node:fs";
import vm from "node:vm";
import { encodeValue, sha256hex } from "../lib/fp-encode.mjs";

let pass = 0, fail = 0;
function ok(label, condition) {
  if (condition) pass++;
  else { fail++; console.log("  ✗ " + label); }
}

const html = readFileSync(new URL("../assets/fingerprint-probe.html", import.meta.url), "utf8");
const start = html.indexOf("function canonicalForControlHash(");
const end = html.indexOf("\n      function runThumbmark()", start);
if (start < 0 || end < 0) throw new Error("control manifest helper boundary not found");

function runManifest(namespace, records, supplied = {}) {
  let emitted = null;
  const context = {
    Object, Array, JSON,
    CUR: { recs: records },
    sha256hex,
    M(path, getter) { emitted = { path, value: getter() }; return emitted.value; },
  };
  vm.runInNewContext(html.slice(start, end)
    + "\nthis.engineManifest=engineManifest;this.ctrlHash=ctrlHash;", context);
  const returned = context.engineManifest(namespace, supplied);
  return { emitted, returned, ctrlHash: context.ctrlHash };
}

const row = (path, valueType, value, meta = {}) => ({ path, valueType, value, meta });

{
  const rows = [
    row("control.thumbmark.zeta", "number", 2),
    row("control.thumbmark.__proto__", "string", "literal"),
    row("control.thumbmark.alpha", "array", [{ valueType: "number", value: 1 }], { count: 1 }),
    row("control.thumbmark.hash", "string", "derived"),
  ];
  const r = runManifest("thumbmark", rows, {
    engine: "thumbmarkjs", version: "1.11.0", status: "ok", errorCount: 0,
    componentCount: 999, componentKeys: ["forged"], hash: "forged", hashAlgorithm: "fnv",
  });
  ok("manifest is emitted in the engine namespace", r.emitted?.path === "control.thumbmark.__manifest");
  ok("component keys are exact, sorted and preserve literal __proto__",
    JSON.stringify(r.returned.componentKeys) === JSON.stringify(["__proto__", "alpha", "zeta"]));
  ok("derived Thumbmark hash is excluded from the raw component set", r.returned.componentCount === 3);
  ok("caller cannot forge manifest count or hash algorithm",
    r.returned.hashAlgorithm === "sha256" && /^[0-9a-f]{64}$/.test(r.returned.hash));
  const expected = Object.create(null);
  expected.__proto__ = { valueType: "string", value: "literal", meta: {} };
  expected.alpha = { valueType: "array", value: [{ valueType: "number", value: 1 }], meta: { count: 1 } };
  expected.zeta = { valueType: "number", value: 2, meta: {} };
  ok("manifest hash covers the exact encoded row identities", r.returned.hash === r.ctrlHash(expected));
}

{
  const fp = runManifest("fingerprintjs", [
    row("control.fingerprintjs.canvas", "object", { props: {} }),
    row("control.fingerprintjs.visitorId", "string", "derived"),
  ], { status: "ok", errorCount: 0 });
  const scanner = runManifest("fpscanner", [
    row("control.fpscanner.rawSignal", "boolean", true),
    row("control.fpscanner.test.webdriver", "object", { props: {} }),
  ], { status: "ok", errorCount: 0 });
  ok("FingerprintJS visitorId is not misdeclared as a raw component",
    JSON.stringify(fp.returned.componentKeys) === JSON.stringify(["canvas"]));
  ok("FPScanner derived test verdicts are not misdeclared as raw signals",
    JSON.stringify(scanner.returned.componentKeys) === JSON.stringify(["rawSignal"]));
}

{
  const r = runManifest("clientjs", [
    row("control.clientjs.same", null, null),
    row("control.clientjs.same", "number", 1),
  ], { status: "ok", errorCount: 1 });
  ok("duplicate raw component rows remain visible for server rejection",
    JSON.stringify(r.returned.componentKeys) === JSON.stringify(["same", "same"]));
}

{
  const scannerStart = html.indexOf("function runFpscanner()");
  const scannerEnd = html.indexOf("// REAL ClientJS engine", scannerStart);
  async function runScanner(analyseFingerprint) {
    const records = [];
    const root = {
      fpCollect: { generateFingerprint: async () => ({ userAgent: "Chrome", rawSignal: true }) },
      fpScanner: {
        TESTS: { FIRST: "TEST_FIRST", SECOND: "TEST_SECOND" },
        analyseFingerprint,
      },
    };
    const context = {
      Promise, Object, Array, JSON, String,
      root,
      CUR: { recs: records },
      sha256hex,
      nowMs: () => 10,
      loadScript: async () => true,
      M(path, getter) {
        const value = getter();
        const encoded = encodeValue(value);
        const meta = {};
        if (encoded.special != null) meta.special = encoded.special;
        if (encoded.count != null) meta.count = encoded.count;
        records.push({ path, valueType: encoded.valueType, value: encoded.value, meta });
        return value;
      },
    };
    vm.runInNewContext(html.slice(start, end) + html.slice(scannerStart, scannerEnd)
      + "\nthis.runFpscanner=runFpscanner;", context);
    return { manifest: await context.runFpscanner(), records };
  }

  const healthy = await runScanner(() => ({
    TEST_FIRST: { consistent: 3, data: { a: 1 } },
    TEST_SECOND: { consistent: 2, data: { b: 2 } },
  }));
  ok("FPScanner manifest binds the exact analyser test set and encoded test rows",
    healthy.manifest.status === "ok" && healthy.manifest.errorCount === 0
      && healthy.manifest.testCount === 2
      && JSON.stringify(healthy.manifest.testKeys) === JSON.stringify(["TEST_FIRST", "TEST_SECOND"])
      && JSON.stringify(healthy.manifest.expectedTestKeys) === JSON.stringify(["TEST_FIRST", "TEST_SECOND"])
      && /^[0-9a-f]{64}$/.test(healthy.manifest.testSetHash)
      && healthy.manifest.testKeySetHash === healthy.manifest.expectedTestKeySetHash
      && healthy.records.filter((record) => record.path.startsWith("control.fpscanner.test.")).length === 2);

  const thrown = await runScanner(() => { throw new TypeError("analyser failed"); });
  ok("FPScanner analyser exceptions fail the engine closed",
    thrown.manifest.status === "analysis-error" && thrown.manifest.errorCount === 1
      && thrown.manifest.testCount === 0 && thrown.manifest.error === "ERR:TypeError");

  const incomplete = await runScanner(() => ({
    TEST_FIRST: { consistent: 3, data: {} },
  }));
  ok("missing or extra FPScanner tests cannot produce an ok manifest",
    incomplete.manifest.status === "analysis-invalid" && incomplete.manifest.errorCount === 1
      && incomplete.manifest.testCount === 1
      && incomplete.manifest.testKeySetHash !== incomplete.manifest.expectedTestKeySetHash);
}

console.log(`\nfp-controls: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
