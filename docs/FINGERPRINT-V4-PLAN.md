# Fingerprint module — v4 execution plan (after Codex review)

Codex's review is **accepted**. Prior "12/12" was overclaimed; the honest status
is completed/partial/not-proven. This is the tracker to a reviewable v4.

## Accepted corrections to the 3 deviations
1. **FingerprintJS** — my BSL objection was **stale**. FingerprintJS **OSS v5 is MIT**
   again (BSL was v4). → vendor `@fingerprintjs/fingerprintjs@5.x` (pinned, self-hosted,
   no CDN, full components+errors+durations, MIT NOTICE). Runs **parallel** to Thumbmark.
2. **CreepJS** — MIT code; extractable. → self-hosted renamed adapter under our namespace
   `control.consistency.*`, no upstream UI/backend, THIRD_PARTY_NOTICES, pinned commit+SHA.
   Trademark: don't ship the CreepJS name/logo as our feature.
3. **Server-side type view — REJECTED.** Types must be produced **in the browser at
   collection time**. Server can't recover false vs "false", null vs "null", NaN, arrays, etc.
   → typed envelope is the source of truth (Phase 1, started).

## Phases (keystone first — everything downstream depends on typed raw)

- **P1 Typed schema at collection** — `encodeValue`/`walkTyped`/STATUS enum in the probe,
  record = `{path,context,phase,status,valueType,value,error,meta}`.
  - [x] P1a encoder + regression test (`scripts/fp-encode.test.cjs`, 21/21) + typed deep-walk
        (navigator/screen/window/document) emitted as `_measurements`, non-breaking. **DONE.**
  - [ ] P1b migrate every block probe to `encodeMeasurement(path,ctx,phase,fn)` — kill the
        `S()`/`A()` sentinels (`'undef'`, `'ERR:*'`) so blocks are typed too.
  - [ ] P1c worklet realm typed (own adapter): DSP output, structured `hasNavigator` status.
- **P2 Known-bug fixes** (all get regression tests): locale.firstWeekday, listFormat (call it,
  don't `typeof`), webgpu.isFallback, Math acos/asin/atanh valid inputs, Error real stack frames,
  worker codec `no-el`, WorkerNavigator prototype/descriptor lookup, unavailable≠leaked/masked.
- **P3 Rich probes** (3 internal repeats + stability + raw/blobRef + input-length + SHA-256):
  Canvas, WebGL1/2 (independent), WebGPU (adapter/render/compute/shader-info/device-lost),
  Audio offline/realtime/worklet DSP, WebRTC (repeated offers, ICE completion+candidates,
  stable/volatile decomposition).
- **P4 Realm matrix + manifests** — same-origin iframe by real URL, true cross-site OOPIF (with
  process-isolation proof + parent/child origin/site in meta), sandboxed + credentialless iframe
  (flags kept), worker classic+module, shared classic+module, service-worker install/activate/
  control. Per-realm `context-manifest.json` (expected/ran/finished/unsupported/blocked/timeout/
  duration/probes). Explicit `blocked`/`unsupported` records — never silent absence.
- **P5 Permissioned phase** — button-gated; all prompts handled; `phase-manifest.json`; skipped
  phase ⇒ permissionedStatus=INCOMPLETE.
- **P6 Network raw (plain + anti)** — `plain.net.jsonl`/`anti.net.jsonl` with IP, HTTP version,
  header names+values+order, UA, Accept-Language, Sec-CH-UA + high-entropy CH, Fetch Metadata,
  Priority, Accept-CH/Critical-CH, TLS ClientHello meta, JA3, **JA4**, ALPN, cipher/ext meta,
  HTTP/2 SETTINGS + pseudo-header order + flow/window, HTTP/3/QUIC, WS/WebTransport routes,
  WebRTC ICE/STUN, DNS status, parser version, capture build hash. Unsupported ⇒ structured
  status, not a vanished field. Document which layer terminates TLS (must be our endpoint).
- **P7 Control engines (4, self-hosted, pinned, offline)** — Thumbmark (`logging:false` + a test
  asserting **zero external requests**), FingerprintJS OSS v5, FPScanner (verify+pin by commit),
  renamed CreepJS adapter. All: exact version + upstream commit + SHA-256 of src & build,
  THIRD_PARTY_NOTICES.md + third_party/licenses/, lockfile, transitive-license check, SBOM,
  no-external-request test. Engines give raw components, they DON'T judge good/bad antik.
- **P8 Validator model** — split statuses: `integrityStatus` PASS/FAIL · `schemaStatus`
  CURRENT/LEGACY_LOSSY/INVALID · `coverageStatus` · `permissionedStatus` · `networkStatus` ·
  `controlStatus` · `employeeReady`. Incomplete may export for debug, never as employee-ready.
- **P9 Comparator** — only compare when both sides status=ok; `leaked`/`masked` ONLY with an
  explicit expected-target rule; else same/different/plain-only/anti-only/unresolved; volatile
  & unstable separate; plain/anti valueType shown separately; **no leaked/masked without
  anti.profile.json**; hardware/build/locale/screen/network differences are confounders first.
- **P10 Exporters** — Excel/Markdown are DERIVED views over typed raw; per-side status+valueType,
  coverage per realm/phase/engine, missing/error/timeout list, network + control summaries,
  unique-paths vs context-instances, volatile, confounders, no leaked/masked for unavailable,
  long values via blobRef. Arithmetic must reconcile: `raw union = classified + excluded(with reasons)`.
- **P11 Regression/CI** — executable harness (unit + integration + browser smoke). Tests from
  Codex's list. Legacy session `20260901-202731` kept ONCE as
  `tests/fixtures/legacy-incomplete-20260901/` → must resolve to `LEGACY_INCOMPLETE`.
- **P12 v4 source bundle** — small `source-review-v4.zip` (source, tests, manifests, LICENSE/
  NOTICE, lockfile, build/commit hash, diff), NO node_modules/chromium/build cache. One canonical
  `docs/FINGERPRINT-MODULE.md` + `CHANGELOG.md`.

## Order of work
Fix (P1–P10) → run tests (P11) → self smoke-test in Chromium → hand source+tests+hash to Codex →
code-review → **then** the user does ONE fresh paired plain+anti run (same collector, same machine,
passive+permissioned, all internal repeats) → validate → only then give to employees.
The legacy raw is a regression fixture, NOT proof of v3/v4 features.

## Status (updated)
- **P1 DONE** — typed envelope at collection; ALL blocks + ALL realms
  (main/iframe/workers[+module]/service-worker/OOPIF/sandboxed/credentialless/
  audio-worklet) emit typed `_measurements`. Worklet DSP + typify. Encoder 21/21.
- **P2 DONE** — listFormat, firstWeekday, math domain, webgpu.isFallback, codec
  worker `no-el`, error real frames, WorkerNavigator descriptor, worklet.hasNavigator.
- **P3 DONE** — canvas/webgl1+2/audio: 3 repeats + stability + input-length + SHA;
  audio offline/realtime split. (WebGPU render/compute + WebRTC ICE = later polish.)
- **P4 DONE** — module workers, sandboxed + credentialless iframe, isolation metadata,
  EXPECTED_CONTEXTS matrix. (Real-URL same-origin frame = later polish.)
- **P5 DONE** — permissioned phase manifest + structured permission statuses.
- **P6 DONE (source)** — capture-server net record: header names+order, Client Hints,
  Fetch Metadata, HTTP version, provenance. (Redeploy VPS fp-capture to activate.)
- **P7 2/4** — Thumbmark + FingerprintJS OSS v5 vendored (MIT, telemetry off, SHA).
  FPScanner + renamed CreepJS adapter still pending.
- **P8 DONE** — `lib/fp-schema.mjs` + `validateSessionV4` (split statuses) wired into
  the server (validation.json, ?validationV4=1).
- **P9 DONE** — `lib/fp-compare.mjs` rule engine (unavailable≠leaked; no verdicts
  w/o profile). (Wiring into the live `compare()`/UI = later.)
- **P11 (scaffold)** — `scripts/fp-test.sh`, 108 assertions; legacy fixture. (v4.2:
  suite must exit 0 from the packaged bundle — the fixture ships in the bundle.)
- **P12 partial** — CHANGELOG + source-review bundle built; doc consolidation +
  exporters-on-typed (P10) pending.

## v4.1 status (superseded — NOT accepted)
The v4.1 realm-timeout fix (encodeValue DataCloneError, jobGuard, WebGPU adapter
timeout, JSON-safe posts) landed and the realm matrix now runs with no timeouts.
But the v4.1 claims of `terminal PASSED / 61 pass from bundle / P1–P12 done` were
NOT substantiated and are withdrawn. Session `20260903-160918` is kept as
`tests/fixtures/diagnostic-20260903-160918/` with `readiness=NOT_EMPLOYEE_READY`.

## v4.2 — MANDATORY (Codex re-review). NONE optional/later.
Tracker for the 18 required fixes. Status legend: [ ] todo · [~] in progress · [x] done+proven.

- [~] **1. Test package.** Suite exits 0 (108 assertions); the ENOENT was a
  packaging miss — `tests/fixtures/` must ship IN the v4.2 bundle. Docs reconciled
  to the real count. Session `20260903-160918` saved as
  `tests/fixtures/diagnostic-20260903-160918/` (readiness=NOT_EMPLOYEE_READY).
  REMAINING: include fixtures in the bundle build (done at #10/#12-final packaging).
- [x] **2. One encoder, imported.** DONE. `lib/fp-encode.mjs` is the single
  source: imported by `scripts/fp-encode.test.mjs` AND injected verbatim into the
  probe + collector by `lib/fp-probe-source.ts` (placeholder inside COLLECTOR →
  carried to every realm). Old `fp-encode.test.cjs` copy deleted. Added
  ArrayBuffer/TypedArray content hash + tests for safe-object encoding,
  content-hash, cloneability, JSON round-trip. Suite now 108 assertions, green;
  a vm harness confirms the injected collector encoder == the module in-realm.
- [x] **3. Schema/readiness split.** DONE. `fp-schema.mjs` adds
  `classifyNetworkSchema` (net record graded CURRENT/PARTIAL/MISSING on its own);
  `validateSessionV4` now exposes `browserSchemaStatus` (browser contexts only,
  network excluded) + `networkSchemaStatus`; both feed one authoritative
  `employeeReady`/`overall`. Tests prove a flat net record no longer poisons the
  browser grade.
- [x] **4. Kill legacy `✅ VALID`.** DONE. Markdown (`buildReport`), Excel
  (results route summary), and UI (`FingerprintResults` — list badge + compare
  panel) now show ONE verdict `READY`/`NOT READY` from `v4.overall`, threaded via
  `Comparison.v4`. Integrity is a sub-status, never a competing flag.
- [x] **5. Real session completion.** DONE. `send()` now REJECTS on HTTP non-2xx
  and network failure (+ `SENDLOG` of every ack). The probe records a terminal
  status per realm (`rstat`: finished/timeout/unsupported/blocked/error/fired) and
  posts a `run-manifest` (expected list + per-realm status + acks) LAST, after the
  permissioned phase; «готово» is logged only after that manifest's server ack.
  `validateSessionV4` adds `manifestStatus` (MISSING/INCOMPLETE/COMPLETE) and
  REQUIRES it COMPLETE for `employeeReady` — a landed line is no longer "done".
- [x] **6. Passive/context manifests.** DONE. `jobGuard` timeout now pushes a
  typed `status=timeout` record (`<block>.__job`) in addition to the legacy
  sentinel. `M()`/`MA()` normalise a thrown `SecurityError` to `blocked` (access
  denial, not a bug); any other throw stays `error`. Per-realm terminal status is
  in the run-manifest; per-probe terminal status is in the typed records.
- [x] **7. No duplicate `{context,path}`.** DONE. Root cause fixed in the probe
  (`uachBlock`: getHighEntropyValues echoes brands/mobile → skip re-emit).
  `findDuplicatePaths` in fp-schema; `validateSessionV4` scans raw records per
  context, exposes `duplicateStatus` + `duplicates[]` (blocks readiness), shown in
  MD/Excel/UI. Verified against the real fixture (22 incidents = uach.brands/mobile
  ×2 in 11 realms) and unit-tested. Full raw-vs-collapsed arithmetic lands with #17.
- [x] **8. Permissioned phase rewrite.** DONE. `permissionedCollect` rebuilt:
  permission states before AND after (prompt≠granted); a REAL
  `getUserMedia({audio,video})` → per-track kind/label/settings/capabilities/
  constraints, then tracks STOPPED; `enumerateDevices` before vs after with typed
  per-device kind/label/deviceId/groupId + `labelsRevealed`; geo TYPED
  (lat/lon/accuracy/altitude/altitudeAccuracy/heading/speed/timestamp) + coarse
  bucket as an extra field; manifest reconciles requested vs
  granted/denied/prompt/timeout/unsupported with a `complete` flag = every step
  terminal. Server `permissionedStatus` now requires that `complete` flag on both
  sides. NOTE: typed lat/lon is now stored (operator PII decision — see report).
- [x] **9. Full network raw export.** DONE. The panel zip export now ships
  `plain.net.jsonl`/`anti.net.jsonl` + `network-manifest.json` (schemaStatus +
  parserVersion + captureBuild + tlsTerminatedBy) + per-file `SHA256SUMS.txt`
  alongside the report, so its network section reproduces. `readNetRaw` added.
- [x] **10. Buildable bundle.** DONE. `scripts/build-review-bundle.sh` produces
  `source-review-v4.2.tar.gz` with `lib/ja4.ts`, minimal package.json + generated
  `package-lock.json` + `tsconfig.review.json`, SBOM, `tests/fixtures/`, and a
  `test-ci-log.txt` proving **TYPECHECK: PASS + TESTS: PASS standalone** (npm
  install → typecheck the pure core → run the suite, no repo node_modules). 62
  files, 748K, no node_modules/.next/DB/secrets.
- [~] **11. P6.** MOSTLY DONE (net-v5), honestly NOT claiming full DONE. ADDED:
  observed public IP + family; raw ClientHello cipher/extension/sigAlg lists IN
  WIRE ORDER (GREASE kept) + JA3/JA4; ALPN offered+negotiated; header NAMES **and
  VALUES** in wire order; full high-entropy Client-Hints; **Accept-CH/Critical-CH
  advertised** in the response (round-trip); UA/Accept-Language/Fetch-Metadata/
  Priority. Every unterminated layer is a STRUCTURED status
  (http3Quic/webTransport/webSocket/webrtcStun/dns), never a vanished field.
  REMAINING (the one hard piece): **H2 SETTINGS + pseudo-header order** — node's
  http2 abstracts frame order away, so it needs a raw HTTP/2 frame parse (a
  follow-up mirroring the JA4 ClientHello peek); the endpoint negotiates http/1.1
  today and records that as a structured status.
- [~] **12. True OOPIF.** INFRA DONE. Bought a 2nd registrable domain
  `capture-crosssite.example` → VPS (A+AAAA); Let's Encrypt cert issued; capture
  server serves it via SNI (both `/xprobe` OOPIF and JA4), old `fp.` kept for
  rollback; panel `CAPTURE_URL` switched to it → the cross-origin realm and the
  network layer are now genuinely cross-site. xprobe page records `_isolation`
  (child/parent origin+host, crossOrigin). REMAINING: process-isolation proof +
  schemeful-site assertion from the #14 Playwright smoke; verify in a real run.
- [x] **13. Controls honest.** Keep Thumbmark + FingerprintJS v5; Thumbmark
  components+hash in one run; full components/errors/durations of BOTH into typed
  `_measurements` (not only legacy flat map); `controlStatus` checks version/ok/
  component-count/manifest/errors. Self-written fpscanner/consistency demoted to
  basic sanity checks (NOT counted as engines). 4/4 only if two real independent
  OSS systems are integrated (pinned commit + LICENSE/NOTICE + tests).
  DONE. Vendored + wired 4 REAL, independently-authored engines (thumbmark ·
  fingerprintjs · fpscanner · clientjs); self-written checks demoted to
  `control.sanity.*` (NOT counted). `controlOk()` counts the 4 real engines; full
  components of ALL engines go into typed `_measurements`. FPScanner bundled via
  esbuild (source SHAs pinned, zero XHR/fetch/beacon verified), ClientJS drop-in;
  LICENSE/NOTICE + 6 new fp-vendor SHA/licence/no-network tests. In-browser
  execution of the two new engines is confirmed by the #14 smoke / terminal run.
  DECISION: vendor 2 real OSS (operator). Research verified live (Sept 2026):
  - Control #3 = FPScanner + fp-collect (MIT, antoinevastel) → `control.fpscanner.*`.
    Pin fp-collect src/fpCollect.js SHA-256
    `cb9b75f5ff9e4b89351b78b5948fa415e8c18f1f1383104573a495152bdcbeee` +
    fpscanner@0.1.5 src/fpScanner.js SHA-256
    `5bee77aee550ba9c76a8607f7c85ffccd45b724e9b3a32d10bf5970258fdfbfa`. CommonJS →
    bundle once to an IIFE; inline ua-parser-js 0.7.x (elect MIT) — NEVER 1.x/2.x
    (AGPL). Zero network (only a data:-URI Image). 32 raw signals + per-test verdicts.
  - Control #4 = ClientJS 0.2.1 (Apache-2.0, jackspirou) → rename slot
    `control.consistency.*` → `control.clientjs.*`. Drop-in global, zero build/network.
    Pin client.base.min.js 29 023 B SHA-256
    `4372c83fdb3fc2a44b777c05b005ee4a075a2ee99e41691a33631bc79a0a8acb` (cdnjs 0.2.1).
  - AVOID BotD (same author as engine #2 → not independent) and CreepJS (entangled + TM).
  - Code notes: `controlOk()` hard-codes engine id `consistency` → change to `clientjs`;
    add both to THIRD_PARTY_NOTICES + control/route.ts ENGINES + fp-vendor SHA tests.
- [x] **14. Real browser smoke.** DONE. `scripts/fp-smoke.mjs` (Playwright/
  Chromium) mints a session cookie, drives a REAL collection with granted
  geo/camera/mic (fake media), logs every context request, and asserts **ZERO
  third-party requests** (runtime no-egress proof), all realms
  (main/workers/worklet/iframe/iframe-url/sandboxed/**service-worker**/OOPIF/
  permissioned), the **run-manifest** completion, and all **4 control engines**
  loading. Current result: **PASS — 14 contexts, 4/4 engines, 0 third-party.**
  It already caught + fixed a real prod bug: the SW route wasn't injecting the
  encoder after the #2 refactor (SW realm was silently dead). Also broadened the
  xprobe CSP frame-ancestors to let the localhost smoke exercise the OOPIF.
- [~] **15. Finish active probes.** PARTIAL (biggest gaps closed, live from disk).
  WebGPU: added a real RENDER pass (64×64 rgba8, isolated own-adapter/device,
  pixel read-back + hash, compile messages, device-lost) alongside the existing
  compute. WebRTC: added STRUCTURED candidates (type/protocol/component/family —
  the mdns-vs-ipv4/ipv6 IP-leak signal) on top of the existing offers/ICE/
  capabilities/stability. Audio offline has 3-repeats+stability already; worklet
  DSP exists. REMAINING polish: SHA-256 (not FNV) + raw/blobRef for canvas/audio/
  webgl/webgpu hashes; audio REALTIME render (only baseLatency today); 3-repeat
  stability for the render pass; and a sweep so a probe that short-circuits on a
  MISSING api returns `unavailable` rather than `ok`+undefined.
- [x] **16. Comparator = explicit per-path expectation registry.** DONE.
  `lib/fp-expect.mjs` (single source, imported by server + test) maps each vector
  to the SPECIFIC target paths it's expected to change. Live `compare()` marks
  leaked/masked ONLY when a path is a target of a spoofed vector — else
  `unchanged`/`different`. `webgpu.isFallback`/`*.available`/`*.status` are not
  targets, so they can't be leaked. `vectorFor` now maps `permissioned.geo.*` →
  geolocation. 11 new comparator tests (24 total).
- [x] **17. Excel fixed.** DONE. Summary leads with the authoritative
  READY/NOT-READY + split status rows (integrity/schema×2/dups/coverage/
  permissioned/network/control/manifest); shows ALL verdict categories
  (leaked/masked/different/unchanged/removed/added/unresolved/volatile); unique
  paths vs context-instances; a СВЕРКА block reconciling raw typed records
  (before collapse) vs dups-dropped vs Σ verdicts == compared rows; and a new
  "Проблемы" sheet listing duplicates / error / timeout / blocked / coverage
  gaps. Colour-coding extended to the new verdicts.
- [~] **18. Provenance.** MOSTLY DONE. A `BUILD_ID` (SHA-256 over the module
  source, computed at server start) is now stamped into EVERY stored record
  (`appendRecord`/`writeNetwork`), into `validation.json`, `network-manifest.json`,
  `build-id.txt`, and the run-manifest — so live raw/export provably ties to a
  source tree. SHA256SUMS is kept but no longer billed as a commit+diff. REMAINING:
  the repo isn't git; offer a base-bundle-hash + diff between v4.1 and v4.2 bundles
  (or `git init` the module) so Codex can diff against the reviewed tree.

### Next delivery (only after these pass a source review)
small buildable `source-review-v4.2.tar.gz` (no node_modules/Chromium/cache) +
full test/CI log + package/lock/build manifests + LICENSE/NOTICE/SBOM. Then, and
only then, ONE new paired plain+anti session — accepted iff `employeeReady=true`,
`overall=READY`, all views agree, export carries all raw, and it reproduces from raw.

### Two decisions that gate design (asked of the operator)
- **#12 OOPIF:** second registrable domain pointed at the VPS (true cross-site) vs
  process-isolation-proof-via-smoke (same-site, honestly labelled).
- **#13 controls:** honest 2 engines + 2 sanity checks (drop the 4/4 claim) vs
  vendor two more real OSS engines to legitimately reach 4/4.

## Run the tests
`bash scripts/fp-test.sh`  → 108 assertions across encode/schema/compare/vendor.

## v4.3 — MANDATORY (Codex re-review of v4.2 source). Not limited to prior partials.
Confirmed OK by Codex: archive intact (73 files), 72/72 SHA match, `npm ci` →
typecheck + 139/139, 4 OSS engines physically present, geo=A kept. The
`fingerprints-2026-09-03` export is STALE (byte-identical to the diagnostic
fixture, pre-v4.2 code) → keep only as a regression fixture, not evidence.

- [x] **v43-1 Completion/lifecycle.** Neither server nor UI may treat a side done
  after the first line. Readiness ONLY after a saved terminal run-manifest + all
  canonically-expected contexts + a confirmed network record + server-side
  `validateSessionV4`. `finishAndReport(false)` must NOT be ignored; «✓ готово»
  only after a server ack with `employeeReady=true`.
- [x] **v43-2 Validator.** Expected matrix defined by the SERVER (schema/build/
  browser caps), never trusting the browser's `expected`. `expected=[]` MUST fail.
  Unexpected error/timeout/invalid-result, a missing required context, a duplicate,
  or an unreadable JSONL line ⇒ NOT_READY. Allowed unsupported/blocked states
  enumerated per concrete probe/path, not accepted universally.
- [x] **v43-3 Lossless typed encoder.** Preserve nested object values (incl.
  getSettings/getCapabilities/getConstraints), not just ctor+keys. Remove unmarked
  `slice(0,400)` / array truncation. Large payloads → blobRef + length + SHA-256.
  Tests: nested objects, cycles, function/symbol inside arrays, NaN/Infinity/
  undefined, DataView, ArrayBuffer, typed arrays.
- [x] **v43-4 FPScanner mapping.** 1=INCONSISTENT, 2=UNSURE, 3=CONSISTENT. Keep
  each test's raw `consistent` + `data`; stop collapsing everything-but-false to ok.
- [x] **v43-5 Control engines.** Thumbmark components+hash from ONE run. Per-engine
  typed manifest: engine/version/status/duration/componentCount/errorCount/hash +
  full typed components/errors. controlStatus=COMPLETE only with expected version,
  status=ok, valid componentCount, no fatal error.
- [x] **v43-6 Comparator.** ONE production comparator that the tests actually run.
  Registry from ACTUAL emitted collector paths (canvas.pixelFnv/pixelSha256/
  repeats, WebGL render hashes, webgpu.render.hash are currently unrecognised).
  Contract test: every emitted path has a rule OR an explicit exclusion reason.
  Rules consider MODE, not only vector.
- [x] **v43-7 Smoke/E2E.** Assert RESPONSES + SAVED data, not just outgoing
  requests: response statuses, console/page/request errors, server persistence,
  exact context matrix, zero duplicates, manifests, four engine manifests, network
  record, employeeReady, build IDs. Run BOTH env (paired flow). Network ∈ expected
  contexts. Attach a request ledger + proof of no egress after a quiet period.
- [~] **v43-8 Network.** DONE except H2: JA3-real + JA4 official-vector + fuzz; fired≠ack (capture awaits panel save); MULTI-RECORD ClientHello reassembly (+test); VERSIONED TYPED net-v5 schema (typed arrays/objects); TWO-PHASE Accept-CH (round 1 prime → round 2, round index recorded). RESIDUAL (keeps #8 partial): H2 SETTINGS + pseudo-header order — needs raw HTTP/2 frame + HPACK parsing; the endpoint negotiates http/1.1 and records that as a structured status. `fired` is NOT ack — capture-server must AWAIT the panel
  save and return success only after confirmed persistence. Real two-phase
  Client-Hints (prime Accept-CH → 2nd capture with round index). Strict versioned
  network schema (typed arrays/objects, parser+capture build hash). Close H2
  SETTINGS + pseudo-header order. Rename the incomplete ja3 OR implement real JA3.
  JA4: official vectors + real ClientHello fixtures + fragmented TCP/TLS + GREASE +
  malformed + bounds tests.
- [x] **v43-9 OOPIF.** Prove different eTLD+1 / schemeful sites; check
  `event.origin`; save actual parent/child origins. Playwright/CDP must attach
  renderer/target/process evidence. Remove the old same-site origin from the PASS
  allowlist. Tie the collector cache to a content/build hash (invalidate on update).
- [x] **v43-10 Provenance/build.** BUILD_ID = build-time ROOT hash of the whole
  executable tree (collector/server/UI/routes/export/vendor), not 9 files. Raw
  carries separate browserCollectorBuild / crossOriginCollectorBuild /
  captureServerBuild / panelWriterBuild / vendor-lock hash. Missing files must
  BREAK the build (no empty/partial hash). Full module+routes+UI+exporter must
  really typecheck/build; the build script must not swallow FAIL via `&& … || …`.
- [x] **v43-11 Dependencies/licences.** ClientJS bundles ua-parser-js 0.7.30
  (GHSA-fhg7-m89q-25r3) — rebuild with >=0.7.33/0.7.41 or replace. SBOM +
  THIRD_PARTY_NOTICES: ClientJS Apache-2.0, add fp-collect / ua-parser / JA4
  notices. Add `vendor-lock.json` (upstream URL, tag/commit, source SHAs,
  toolchain, build command, patches, output SHA).
- [x] **v43-12 Export.** Excel has a «Проблемы» sheet, ONE consistent READY/
  NOT_READY, and a REAL `raw union = classified + excluded(with reason)` equation
  (not just Σ of already-created comparator rows). Never VALID beside
  employeeReady=false.

### Next delivery: source-review-v4.3 + full build/typecheck/test log + a new
machine-checkable smoke. Code re-acceptance FIRST; only then ONE final live paired run.
