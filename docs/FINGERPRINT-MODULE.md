# Fingerprint module (v4) — canonical technical description

Measures an employee's browser fingerprint in their ordinary browser (`plain`)
and their anti-detect browser (`anti`), per collection SESSION, and compares the
pair to show what the anti-detect actually replaced vs. what leaked. Version
history is in `CHANGELOG.md`; the phase tracker + Definition of Done in
`docs/FINGERPRINT-V4-PLAN.md`. Term everywhere: **subject** (never «subject»).

## Data model — typed at collection (the v4 keystone)
The probe (`assets/fingerprint-probe.html`) produces a **typed measurement
envelope in the browser**, at collection time — never reconstructed on the server:

```
{ path, context, phase, status, valueType, value, error, meta }
```

- `status` ∈ closed enum: `ok · unsupported · unavailable-in-context ·
  permission-required · permission-denied · blocked · timeout · error · invalid-result`.
- `valueType` ∈ `null·undefined·boolean·string·number·bigint·symbol·function·
  array·object·arraybuffer·typedarray·error`. Native types are preserved: `false`
  is a boolean, arrays stay arrays (`meta.count===length`), NaN/Infinity/-0/bigint
  are explicit (`meta.special`), a thrown probe goes to `error` (never into `value`).
- `M()`/`MA()` wrap every probe (typed record + a legacy string for back-compat);
  `MSTATUS.*` lets a probe declare an explicit non-ok status instead of a fake value.
- The typed records ride in each context payload as `_measurements`;
  `lib/fp-schema.mjs` classifies a session CURRENT / MIXED / LEGACY_LOSSY / INVALID.

## Realms (browser) + network + control engines — kept separate
- **browser realms**: main-frame · same-origin srcdoc iframe · real-URL same-origin
  frame (`/fingerprint/frame`) · sandboxed iframe · credentialless iframe ·
  dedicated & shared workers (classic + module) · service-worker · cross-site OOPIF
  (`/xprobe` on the JA4 host) · audio-worklet (with a DSP result). Each records its
  isolation metadata; missing realms are explicit `blocked`/`unsupported`, never silent.
- **network** (`scripts/capture-server.mjs`, `capture-samesite.example:8443`): JA4/JA3,
  TLS/ALPN/cipher/ext, HTTP version, header names+order, Client Hints, Fetch Metadata,
  provenance. TLS terminates on our capture endpoint.
- **control engines** (independent, self-hosted, telemetry OFF, pinned + SHA): ThumbmarkJS,
  FingerprintJS OSS v5 (MIT), plus original `control.fpscanner.*` and `control.consistency.*`
  adapters. Raw components only — they never feed our verdicts.

## Validation — separate statuses (never one VALID flag)
`validateSessionV4` (in `validation.json` / `?validationV4=1`): `integrityStatus ·
schemaStatus · coverageStatus · permissionedStatus · networkStatus · controlStatus ·
employeeReady`. An incomplete snapshot may be exported for debug but is never
`employeeReady`. The legacy `20260901` session → schema `LEGACY_LOSSY`,
`overall=LEGACY_INCOMPLETE` (kept only as `tests/fixtures/legacy-incomplete-20260901`).

## Comparator — facts before verdicts
`compare()` runs on the typed records: compares only when BOTH sides are `ok`; a
side that isn't `ok` is `unresolved` (coverage), NEVER leaked/masked. A difference is
`masked` only when the anti-profile marks that path protected, else `different`;
identical-but-protected is `leaked`. No leaked/masked verdicts without a profile;
volatile paths separate; confounders (hardware/build/locale/screen) shown first;
plain and anti status+type shown apart. Markdown/Excel are derived views and must
reconcile arithmetically (Σ verdicts == rows).

## Tests
`bash scripts/fp-test.sh` — typed encoder, schema/schemaStatus, comparator rules,
vendored-engine SHA pins + telemetry-off, legacy fixture. Run before any change.

## Before employees (terminal human step)
Fix + code-review + CI green, THEN ONE fresh paired plain+anti run in Chromium (same
collector, same machine, passive + permissioned, internal repeats), validated by
`validateSessionV4` → only then hand the collector to subjectи. The legacy raw is a
regression fixture, never proof of v4 features.
