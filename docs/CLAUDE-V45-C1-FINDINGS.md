# C1 real-browser findings on v4.5 one-shot (2026-09-07) — for Codex re-review

Scope: branch `fix/v4.5-c1-browser-findings` = `codex/v4.5-one-shot` (7454363) + one
commit (d82a447) touching `assets/fingerprint-probe.html`, `lib/fp-probe-artifact.mjs`,
`scripts/fp-probe.test.mjs`. 881/881 assertions, TS compile pass. The private panel
integration embeds this tree byte-for-byte and is DEPLOYED with it.

The private C1 smoke (Playwright Chromium 151, `--site-per-process`, against the
deployed panel with the real capture process on both SNI domains) failed twice on
the accepted code; both defects are invisible to node/HTTP tests:

1. `audio-worklet` context never persisted → `missing-context` → run-manifest 409
   `capture-incomplete`. `WORKLET_SRC` prepends the collector bytes; the collector's
   IIFE tail is `})(self)`. `AudioWorkletGlobalScope` exposes `globalThis` but no
   `self` (verified in-browser: typeof self/navigator/TextEncoder/URL/crypto are all
   `undefined` there). The module threw at evaluation; Chromium resolves
   `audioWorklet.addModule()` regardless, so the only visible symptom was
   `AudioWorkletNode cannot be created: The node name 'probe' is not defined`.
   Fix: `var WORKLET_SRC="var self=globalThis;\n"+COLLECTOR_SRC+"\n"+...`.
   Verified: worklet posts 18 keys, `worklet.dsp.hash` computed via the injected
   SHA, `worklet.__manifest` ok.

2. `iframe-url` and `cross-origin-iframe` (both `renderBoundChildProbe`) persisted
   `fonts.error` (`TypeError: Cannot read properties of null (reading 'appendChild')`)
   and `clientRects.status=unavailable-in-context`, which the strict validator
   correctly flags blocking (`unexpected-non-ok`, `required-job-evidence-missing`,
   `collector-contract-missing`). The child skeleton was
   `<!doctype html><meta charset><script>collector</script><script>wrapper</script>`;
   the wrapper collects in a microtask right after the second script, before the
   parser creates the implicit `<body>`, so `document.body` was null. Fix: emit
   `<body>` before the scripts (the srcdoc iframes already do). Bound-child tests
   (deterministic bytes, binding ack, vm handshake) unchanged and green.

After the fix the deployed one-shot run is READY on both sides (plain + anti):
14/14 contexts, network rounds 1+2 on the exact capture origin, OOPIF in a
separate renderer (process-internals parent=6 / child=11 bound in the evidence
artifact), zero third-party egress, zero page errors.

Not changed: schema, validator, readiness, store, routes. Collector build id
changes (new artifact/evidence provisioned by the C1 smoke).
