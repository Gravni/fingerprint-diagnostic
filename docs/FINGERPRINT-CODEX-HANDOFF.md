# Fingerprint module v4.3 — handoff for Codex re-review

Everything needed to re-review v4.3. Panel test-result exports are delivered
separately by the operator. Full per-item detail + exact pins are in
`docs/FINGERPRINT-V4-PLAN.md` (v4.3 section). **v4.3 is NOT fully done: #8 remains
partial (H2).** No live paired run has been done — code re-acceptance first.

## 0. TL;DR
- All 12 v4.3 P0s addressed: **11 fully done, #8 partial** (H2 SETTINGS +
  pseudo-header order is the sole residual — needs raw HTTP/2 frame + HPACK
  parsing; the endpoint negotiates http/1.1 and records that as a structured
  status). Nothing else deferred.
- Unit suite: `bash scripts/fp-test.sh` → **207 assertions across encode / schema /
  compare / vendor / ja4, exit 0**.
- Runtime smoke (`scripts/fp-smoke.mjs`, Playwright, `--site-per-process`) → **PASS**:
  14 contexts, 4/4 real engines, **server-confirmed side COMPLETE**, zero
  duplicate {context,path}, all-2xx responses, **cross-site OOPIF is a separate
  renderer target**, and **no third-party egress in the quiet window**. Artifacts:
  `smoke-artifacts/` (screenshot, report, request ledger).
- Bundle build gates are real (Codex #10): FULL repo typecheck + tests + standalone
  typecheck + standalone tests all gate the build (no `|| swallow`); a missing
  source file aborts the rootBuildId.

## 1. The 12 v4.3 items
| # | Item | State |
|---|---|---|
| 1 | Completion/lifecycle — «готово» only after server-confirmed side-status | done (finalised with #2) |
| 2 | Validator — server canonical matrix; expected=[] fails; unreadable JSONL ⇒ NOT_READY; enumerated allowed non-ok per path/context | done |
| 3 | Lossless encoder — recursive nested values, cycles, sync SHA-256, blobRef; no `slice(0,400)` | done |
| 4 | FPScanner mapping 1=INCONSISTENT/2=UNSURE/3=CONSISTENT + raw consistent/data | done |
| 5 | Control engines — per-engine typed manifest; controlStatus graded on version/ok/count/errors; Thumbmark one run | done |
| 6 | Comparator — one production impl; registry from ACTUAL emitted paths; mode-aware; contract test (every emitted path target-or-excluded) | done |
| 7 | Smoke/E2E — persistence + responses + employeeReady(side) + dups + build IDs + request ledger + quiet no-egress | done |
| 8 | Network | **PARTIAL** — done: real JA3 (ext 10/11), JA4 official vector + fuzz, fired≠ack (capture awaits panel save), MULTI-RECORD ClientHello reassembly, VERSIONED TYPED net-v5 schema, TWO-PHASE Accept-CH (round index). **Residual: H2 SETTINGS + pseudo-header order (raw HTTP/2 + HPACK).** |
| 9 | OOPIF — 2nd registrable domain (capture-crosssite.example), event.origin verified + parent/child origins recorded, CDP separate-renderer-target evidence, same-site dropped from PASS, collector cache keyed by build hash | done |
| 10 | Provenance — rootBuildId over the WHOLE executable tree (missing file aborts); per-component builds (browser/cross-origin/capture/panel/vendor-lock) in raw + validation.json + builds.json; build script gates don't swallow FAIL | done |
| 11 | Deps/licences — ClientJS REBUILT with ua-parser 0.7.41 (0.7.30/GHSA gone); vendor-lock.json; fp-collect/ua-parser/JA4 notices | done |
| 12 | Export — real `raw union = classified + excluded(reason)` equation (balances on real data); one READY/NOT-READY; «Проблемы» sheet | done |

## 2. Verify
1. `sha256sum -c SHA256SUMS.txt`
2. `npm install && npm run typecheck && npm test` (see `test-ci-log.txt` — full repo typecheck + tests + standalone all gated).
3. Runtime: `node scripts/fp-smoke.mjs` against the live panel → PASS (needs server + capture host up). See `smoke-artifacts/`.
4. JA3/JA4 vectors: `node --experimental-strip-types scripts/fp-ja4.test.mts` (official salesforce JA3 + FoxIO JA4 + multi-record + fuzz).

## 3. The one residual (keeps #8 partial)
**#8 H2 SETTINGS + pseudo-header order.** node's http2 abstracts frame order away;
capturing it needs a raw HTTP/2 frame + HPACK parser (mirroring the JA4 ClientHello
peek). The endpoint negotiates http/1.1 today and records H2 fields as a structured
"not-captured (needs raw h2 frame parse)" status. Not claimed done.

## 4. NOT in this bundle
node_modules, .next, Chromium, SQLite DB, secrets, panel test-result exports.
