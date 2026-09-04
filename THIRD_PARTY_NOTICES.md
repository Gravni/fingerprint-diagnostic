# Third-party notices

Vendored, self-hosted CONTROL engines for the fingerprint module. All are pinned
MIT builds served locally (no runtime CDN) with telemetry disabled, and run only
as independent controls — their raw components go under `control.*` and never
feed our verdicts. SHA-256 pins are enforced by `scripts/fp-vendor.test.mjs`.

| Engine | Version | File | License | SHA-256 | Telemetry |
|---|---|---|---|---|---|
| ThumbmarkJS | 1.11.0 | `assets/vendor/thumbmark/thumbmark-1.11.0.umd.js` | MIT | `5a12ec3d520aa95b7df0e54ab653c9c594cb8d89a430011c01cd1f8a5deb4bae` | `logging:false` |
| FingerprintJS (OSS) | 5.0.0 | `assets/vendor/fingerprintjs/fp.v5.0.0.umd.min.js` | MIT | `d089678feb7cd84853cb5f0266d6568a3c751c3c204545b70c9013c29cc292f1` | `monitoring:false` |
| FPScanner (+fp-collect) | 0.1.5 / fp-collect 1.0.5 | `assets/vendor/fpscanner/fpscanner.bundle.js` | MIT | `8414f22e6f2466dae55c37b8c8375344679f9469f58590a333d00a16bdc6982c` (our build) | none (no XHR/fetch/beacon) |
| ClientJS | 0.2.1 (rebuilt) | `assets/vendor/clientjs/clientjs-0.2.1.base.min.js` | Apache-2.0 | `5077379fc482d99daeceafb9b63cac07e24f29c6dfba28c445baf3f2ce4d9f22` (our rebuild) | none (self-contained) |

Control engines 3 & 4 are now REAL, independently-authored OSS systems (Codex
v4.2 #13) — four distinct authors: thumbmarkjs · fingerprintjs · antoinevastel ·
jackspirou. The former self-written checks are DEMOTED to basic sanity checks
under `control.sanity.*` and are NOT counted toward the 4/4 engine status.

- **FPScanner + fp-collect** — https://github.com/antoinevastel/fpscanner (MIT) +
  https://github.com/antoinevastel/fp-collect (MIT). CommonJS, so bundled ONCE to a
  browser IIFE (`window.fpCollect` / `window.fpScanner`) with **ua-parser-js 0.7.40
  inlined** (dual `GPL-2.0 OR MIT` → we elect **MIT**; NEVER 1.x/2.x which is AGPL).
  Source SHA-256 pins (in `assets/vendor/fpscanner/src/`): fp-collect
  `cb9b75f5ff9e4b89351b78b5948fa415e8c18f1f1383104573a495152bdcbeee`, fpScanner
  `5bee77aee550ba9c76a8607f7c85ffccd45b724e9b3a32d10bf5970258fdfbfa`, ua-parser
  `95a6709df518be681ad7f8ac624cc5529f1c066d66a33fd1fdc1276d518fd60e`.
  Reproduce the bundle: `esbuild@0.24.0 entry.js --bundle --format=iife
  --alias:ua-parser-js=./ua-parser.js --minify` where entry.js sets
  `window.fpCollect=require('./fpCollect.js'); window.fpScanner=require('./fpScanner.js')`.
- **ClientJS 0.2.1** — https://github.com/jackspirou/clientjs (Apache-2.0), commit
  `8f98834b19440cb6bc96048d23b8886d4e32dddc`. Drop-in browser global
  `window.ClientJS`, self-contained, no network. **REBUILT from source** (webpack,
  `--openssl-legacy-provider`) with **ua-parser-js pinned to 0.7.41** — the upstream
  prebuilt dist froze the vulnerable **0.7.30** (GHSA-fhg7-m89q-25r3 /
  CVE-2022-25927, ReDoS); our rebuild ships 0.7.41 (patched). Apache-2.0 NOTICE +
  attribution kept.

Additional bundled sources (see `assets/vendor/vendor-lock.json` for pins):
- **fp-collect 1.0.5** — https://github.com/antoinevastel/fp-collect (MIT), the
  collector fpscanner consumes; bundled inside `fpscanner.bundle.js`.
- **ua-parser-js 0.7.40** — https://github.com/faisalman/ua-parser-js — dual
  `GPL-2.0 OR MIT`; we **elect MIT**. Inlined into `fpscanner.bundle.js` (>=0.7.33,
  so NOT affected by GHSA-fhg7-m89q-25r3). NEVER 1.x/2.x (AGPL-3.0).
- **JA4 / JA3** (`lib/ja4.ts`) — our OWN implementation of the JA4 spec
  (https://github.com/FoxIO-LLC/ja4, BSD-3-Clause spec) and the canonical
  salesforce JA3 (https://github.com/salesforce/ja3, BSD-3-Clause). No upstream
  code copied; validated in `scripts/fp-ja4.test.mts` against their official vectors.

Upstream:
- ThumbmarkJS — https://github.com/thumbmarkjs/thumbmarkjs (MIT). Local changes: none.
- FingerprintJS OSS v5 — https://github.com/fingerprintjs/fingerprintjs (MIT, **not** Pro).
  Local changes: none. See `assets/vendor/fingerprintjs/NOTICE.md`.

Control engines 3 & 4 — ORIGINAL adapters (no third-party code vendored):
- `control.fpscanner.*` — our own implementation of FPScanner's public bot/headless
  check set (webdriver, headless UA, chrome object/runtime, zero plugins, empty
  languages, Notification-vs-permission, appVersion-in-UA). Independent of the
  fp-collect input format the 2018 lib needs.
- `control.consistency.*` — our own implementation of the CreepJS "lie/consistency"
  concept (UA↔platform match, native toString, languages↔language, hardware/memory,
  productSub, vendor), renamed per the CreepJS trademark policy.
These are ORIGINAL implementations of the public check concepts — no FPScanner or
CreepJS source is copied — so they carry no upstream licence obligation. If a literal
vendored FPScanner (MIT, pin by commit) or a CreepJS module extraction is later
preferred, it slots into the same controlBlock.

Per-engine LICENSE text is kept beside each vendored file (`assets/vendor/*/LICENSE`).
