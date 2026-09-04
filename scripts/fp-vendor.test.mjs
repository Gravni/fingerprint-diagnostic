// Vendored control-engine integrity (Codex v4 §Control): pinned SHA-256 so a
// build can't be silently swapped, and a static check that telemetry is disabled
// in the probe's control loader (the browser smoke-test asserts zero external
// requests at runtime; this catches the config regression cheaply).
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
let pass = 0, fail = 0;
const ok = (label, cond) => { if (cond) pass++; else { fail++; console.log("  ✗ " + label); } };
const sha = (p) => createHash("sha256").update(readFileSync(join(root, p))).digest("hex");

// Pinned SHA-256 — must match THIRD_PARTY_NOTICES.md and each NOTICE.
const PINS = {
  "assets/vendor/thumbmark/thumbmark-1.11.0.umd.js": "5a12ec3d520aa95b7df0e54ab653c9c594cb8d89a430011c01cd1f8a5deb4bae",
  "assets/vendor/fingerprintjs/fp.v5.0.0.umd.min.js": "d089678feb7cd84853cb5f0266d6568a3c751c3c204545b70c9013c29cc292f1",
  // Control engines #3/#4 (Codex v4.2 #13). ClientJS is the upstream file;
  // fpscanner.bundle.js is OUR esbuild artifact (source SHAs + build cmd in
  // THIRD_PARTY_NOTICES). fp-collect/fpScanner/ua-parser sources pinned too.
  "assets/vendor/clientjs/clientjs-0.2.1.base.min.js": "5077379fc482d99daeceafb9b63cac07e24f29c6dfba28c445baf3f2ce4d9f22",
  "assets/vendor/fpscanner/fpscanner.bundle.js": "8414f22e6f2466dae55c37b8c8375344679f9469f58590a333d00a16bdc6982c",
  "assets/vendor/fpscanner/src/fpCollect.js": "cb9b75f5ff9e4b89351b78b5948fa415e8c18f1f1383104573a495152bdcbeee",
  "assets/vendor/fpscanner/src/fpScanner.js": "5bee77aee550ba9c76a8607f7c85ffccd45b724e9b3a32d10bf5970258fdfbfa",
};
for (const [file, want] of Object.entries(PINS)) ok("SHA pinned: " + file, sha(file) === want);

// License present for each vendored engine.
ok("FingerprintJS LICENSE is MIT", /MIT License/.test(readFileSync(join(root, "assets/vendor/fingerprintjs/LICENSE"), "utf8")));
ok("FPScanner LICENSE is MIT", /MIT License/.test(readFileSync(join(root, "assets/vendor/fpscanner/LICENSE"), "utf8")));
ok("ClientJS LICENSE is Apache-2.0", /Apache License/.test(readFileSync(join(root, "assets/vendor/clientjs/LICENSE"), "utf8")));
// The vendored FPScanner bundle must make ZERO network calls (telemetry-free).
const fpbundle = readFileSync(join(root, "assets/vendor/fpscanner/fpscanner.bundle.js"), "utf8");
ok("FPScanner bundle has no XHR/fetch/beacon", !/XMLHttpRequest|fetch\(|sendBeacon/.test(fpbundle));
// ClientJS was rebuilt to drop ua-parser-js 0.7.30 (GHSA-fhg7-m89q-25r3) → 0.7.41.
const cjs = readFileSync(join(root, "assets/vendor/clientjs/clientjs-0.2.1.base.min.js"), "utf8");
ok("ClientJS no longer bundles vulnerable ua-parser 0.7.30", cjs.indexOf("0.7.30") < 0);
ok("ClientJS bundles patched ua-parser 0.7.41", cjs.indexOf("0.7.41") >= 0);
// vendor-lock.json present with an entry per engine (Codex v4.3 #11).
const lock = JSON.parse(readFileSync(join(root, "assets/vendor/vendor-lock.json"), "utf8"));
for (const id of ["thumbmark", "fingerprintjs", "fpscanner", "clientjs"])
  ok("vendor-lock has " + id, lock.engines && lock.engines[id] && lock.engines[id].outputSha256);
// 4 real engines wired in the control loader, sanity checks demoted.
ok("control loader runs 4 real engines", /runThumbmark\(\),runFingerprintjs\(\),runFpscanner\(\),runClientjs\(\)/.test(readFileSync(join(root, "assets/fingerprint-probe.html"), "utf8")));

// The probe's control loader must disable telemetry for both engines.
const probe = readFileSync(join(root, "assets/fingerprint-probe.html"), "utf8");
ok("FingerprintJS loaded with monitoring:false", /FingerprintJS[\s\S]{0,80}\{monitoring:false\}|load\(\{monitoring:false\}\)/.test(probe));
ok("Thumbmark logging disabled", /setOption\('logging',false\)/.test(probe));
// And it must never load an engine from a remote CDN at runtime.
ok("no runtime CDN for control engines", !/src\s*=\s*["']https?:\/\/[^"']*fingerprint|src\s*=\s*["']https?:\/\/[^"']*thumbmark/i.test(probe));

console.log(`\nfp-vendor: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
