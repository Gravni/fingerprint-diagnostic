// Vendored control-engine integrity. vendor-lock.json is the only artifact/source
// digest inventory; this test consumes it rather than maintaining a second set of
// hashes. Runtime no-egress remains an integration-browser gate.
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } };
const sha = (p) => createHash("sha256").update(readFileSync(join(root, p))).digest("hex");
const isSha256 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const isRepoFile = (value) => typeof value === "string"
  && value.length > 0
  && !value.startsWith("/")
  && !value.split(/[\\/]/).includes("..");

const lock = JSON.parse(readFileSync(join(root, "assets/vendor/vendor-lock.json"), "utf8"));
ok("vendor-lock schema is explicit", lock.schemaVersion === 1);
const expectedEngines = ["clientjs", "fingerprintjs", "fpscanner", "thumbmark"];
ok(
  "vendor-lock has exactly the four control engines",
  Object.keys(lock.engines || {}).sort().join(",") === expectedEngines.join(","),
);
const declaredVendorJs = [];
for (const [id, engine] of Object.entries(lock.engines || {})) {
  ok(`${id}: artifact path is repository-relative`, isRepoFile(engine.file));
  ok(`${id}: artifact digest is SHA-256`, isSha256(engine.outputSha256));
  if (isRepoFile(engine.file) && isSha256(engine.outputSha256)) {
    ok(`${id}: artifact matches vendor-lock`, sha(engine.file) === engine.outputSha256);
  }
  if (isRepoFile(engine.file)) declaredVendorJs.push(engine.file);
  for (const [source, digest] of Object.entries(engine.sources || {})) {
    ok(`${id}: source path is repository-relative: ${source}`, isRepoFile(source));
    ok(`${id}: source digest is SHA-256: ${source}`, isSha256(digest));
    if (isRepoFile(source) && isSha256(digest)) {
      ok(`${id}: source matches vendor-lock: ${source}`, sha(source) === digest);
    }
    if (isRepoFile(source)) declaredVendorJs.push(source);
  }
  ok(`${id}: license files are enumerated`, Array.isArray(engine.licenseFiles) && engine.licenseFiles.length > 0);
  for (const licenseFile of engine.licenseFiles || []) {
    ok(`${id}: license path is repository-relative: ${licenseFile}`, isRepoFile(licenseFile));
    if (isRepoFile(licenseFile)) {
      ok(`${id}: license file is non-empty: ${licenseFile}`, readFileSync(join(root, licenseFile)).length > 0);
    }
  }
}

function vendorJavaScriptFiles(directory, relative = "assets/vendor") {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const childRelative = `${relative}/${entry.name}`;
    if (entry.isDirectory()) files.push(...vendorJavaScriptFiles(join(directory, entry.name), childRelative));
    else if (entry.isFile() && entry.name.endsWith(".js")) files.push(childRelative);
  }
  return files.sort();
}
const actualVendorJs = vendorJavaScriptFiles(join(root, "assets/vendor"));
ok("every vendored JavaScript file is declared exactly once in vendor-lock",
  new Set(declaredVendorJs).size === declaredVendorJs.length
    && declaredVendorJs.slice().sort().join("\n") === actualVendorJs.join("\n"));

const clientComponents = lock.engines?.clientjs?.embeddedComponents;
ok("ClientJS embedded components are inventoried", Array.isArray(clientComponents) && clientComponents.length > 0);
if (Array.isArray(clientComponents)) {
  ok(
    "ClientJS embedded component IDs are unique",
    new Set(clientComponents.map((component) => component.id)).size === clientComponents.length,
  );
  for (const component of clientComponents) {
    ok(`ClientJS component ${component.id || "<missing>"} has a version`, typeof component.version === "string" && component.version.length > 0);
    ok(`ClientJS component ${component.id || "<missing>"} has a license`, typeof component.license === "string" && component.license.length > 0);
    ok(`ClientJS component ${component.id || "<missing>"} has provenance`, typeof component.provenance === "string" && component.provenance.length > 0);
  }
}

// Limited static scan for common request APIs. This is not proof of runtime
// no-egress; the browser request ledger remains authoritative.
const fpbundle = readFileSync(join(root, "assets/vendor/fpscanner/fpscanner.bundle.js"), "utf8");
ok("FPScanner limited scan finds no XHR/fetch/beacon", !/XMLHttpRequest|fetch\(|sendBeacon/.test(fpbundle));
// ClientJS was rebuilt to drop ua-parser-js 0.7.30 (GHSA-fhg7-m89q-25r3) → 0.7.41.
const cjs = readFileSync(join(root, "assets/vendor/clientjs/clientjs-0.2.1.base.min.js"), "utf8");
ok("ClientJS no longer bundles vulnerable ua-parser 0.7.30", cjs.indexOf("0.7.30") < 0);
const clientUaParser = Array.isArray(clientComponents)
  ? clientComponents.find((component) => component.id === "ua-parser-js")
  : null;
ok("ClientJS inventory identifies embedded ua-parser-js", !!clientUaParser);
if (clientUaParser) {
  ok("ClientJS artifact contains inventoried ua-parser-js version", cjs.includes(clientUaParser.version));
}
// 4 real engines wired in the control loader, sanity checks demoted.
ok("control loader runs 4 real engines", /runThumbmark\(\),runFingerprintjs\(\),runFpscanner\(\),runClientjs\(\)/.test(readFileSync(join(root, "assets/fingerprint-probe.html"), "utf8")));

// The probe's control loader must disable telemetry for both engines.
const probe = readFileSync(join(root, "assets/fingerprint-probe.html"), "utf8");
ok("FingerprintJS loaded with monitoring:false", /FingerprintJS[\s\S]{0,80}\{monitoring:false\}|load\(\{monitoring:false\}\)/.test(probe));
ok("Thumbmark logging disabled", /setOption\('logging',false\)/.test(probe));
for (const [id, engine] of Object.entries(lock.engines || {})) {
  const sri = `sha256-${Buffer.from(engine.outputSha256, "hex").toString("base64")}`;
  ok(`${id}: browser loader pins vendor-lock SHA-256 and matching SRI`,
    probe.includes(`${id}:Object.freeze({sha256:'${engine.outputSha256}',sri:'${sri}'})`));
}
ok("control route is bound to exact browser build and vendor digest",
  probe.includes("url.searchParams.set('build',EMBEDDED_COLLECTOR_BUILD)")
    && probe.includes("url.searchParams.set('sha256',spec.sha256)")
    && probe.includes("s.integrity=spec.sri"));
// And it must never load an engine from a remote CDN at runtime.
ok("no runtime CDN for control engines", !/src\s*=\s*["']https?:\/\/[^"']*fingerprint|src\s*=\s*["']https?:\/\/[^"']*thumbmark/i.test(probe));

console.log(`\nfp-vendor: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
