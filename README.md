# Browser Fingerprint Diagnostic (core)

A diagnostic that captures a browser's fingerprint across many execution realms and
the network layer, then compares two browser profiles to judge how consistently
they present themselves. Useful for research into fingerprint surface, browser
privacy testing, and anti-fingerprinting QA.

## What it measures

- **Browser realms:** main frame, dedicated/shared/module workers, audio worklet,
  same-origin / sandboxed / credentialless iframes, real-URL iframe, service worker,
  and a true cross-site OOPIF (separate renderer process).
- **Network layer:** a small TLS-terminating capture server reads the raw
  ClientHello and computes **JA4 / JA3 / JA3S**, ALPN, extensions, curves, and the
  HTTP request-header order. (One item is still open — see Status.)
- **Controls:** four vendored open-source fingerprinting engines run alongside the
  built-in probe for cross-checking — **ThumbmarkJS**, **FingerprintJS (OSS)**,
  **FPScanner + fp-collect**, and **ClientJS**. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Every value is captured through a single typed measurement envelope
(`{path, context, phase, status, valueType, value, error, meta}`) with a lossless,
recursive encoder (stable hashing, cycle-safe, blob-refs for oversized values).

## Status — v4.3

**11 of 12** internal review items are closed. The one remaining open item is:

> **#8 Network — H2 SETTINGS frame + pseudo-header order.** Everything else in the
> network layer is done (real JA3 with curves/point-formats, JA4 against the official
> vector + fuzz, multi-record ClientHello reassembly, versioned typed `net-v5`
> schema, two-phase Accept-CH). The residual needs a **raw HTTP/2 frame + HPACK
> parser** (the endpoint currently negotiates HTTP/1.1 and records H2 fields as a
> structured "not captured" status).

Details and the full item-by-item tracker: [`docs/FINGERPRINT-V4-PLAN.md`](docs/FINGERPRINT-V4-PLAN.md)
and [`docs/FINGERPRINT-CODEX-HANDOFF.md`](docs/FINGERPRINT-CODEX-HANDOFF.md).

## Layout

```
lib/         pure core — ja4.ts, fp-encode.mjs, fp-schema.mjs, fp-expect.mjs,
             fp-vectors.ts, fp-compare.mjs  (dependency-free, standalone-typecheckable)
assets/      fingerprint-probe.html + assets/vendor/* (the four control engines)
scripts/     capture-server.mjs (JA4/TLS) + the unit test suite + fp-test.sh
docs/        module doc, v4 plan, JA4 setup notes, review handoff
tests/       fixtures used by the schema regression tests
```

## Build & test

```bash
# unit suite (Node ≥ 20, no install needed) — 207 assertions
bash scripts/fp-test.sh

# typecheck the standalone core
npm install && npm run typecheck

# JA3/JA4 vectors specifically
node --experimental-strip-types scripts/fp-ja4.test.mts
```

## Notes

- All hostnames/IPs in code and docs are **placeholders** (`*.example`,
  `203.0.113.x`). Point them at your own hosts to run the network layer.
- `lib/` is decoupled and has no framework or database dependency. The web glue
  that wires the probe into an app is intentionally **not** included here.

## License

The diagnostic code in this repository is MIT-licensed (see [`LICENSE`](LICENSE)).
The vendored engines under `assets/vendor/` keep their own upstream licenses
(MIT / Apache-2.0) — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
