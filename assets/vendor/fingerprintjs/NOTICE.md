# FingerprintJS OSS — vendored control engine

- **Package**: `@fingerprintjs/fingerprintjs` (OSS, **not** Fingerprint Pro)
- **Version**: 5.0.0 (pinned)
- **File**: `fp.v5.0.0.umd.min.js`
- **License**: MIT (see `LICENSE`; header in the file)
- **Upstream**: https://github.com/fingerprintjs/fingerprintjs
- **Source**: fetched from `https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@5.0.0/dist/fp.umd.min.js`
- **SHA-256**: `d089678feb7cd84853cb5f0266d6568a3c751c3c204545b70c9013c29cc292f1`
  (pinned; verified by `scripts/fp-vendor.test.mjs`)

## Why OSS v5 (correcting an earlier note)
An earlier review skipped FingerprintJS over a BSL concern. That applied to the
**v4** branch. **OSS v5 is MIT again** — used here.

## Telemetry: OFF (mandatory)
The OSS build makes exactly one external request — a `monitoring` XHR to
`m1.openfpcdn.io/.../npm-monitoring`, gated by the `monitoring` option. The probe
loads it with **`FingerprintJS.load({ monitoring: false })`**, so it performs
**zero external requests** on a measurement stand. No Fingerprint Pro, Smart
Signals, hosted Agent, or commercial backend is used.

## How it's used
Served self-hosted from `/fingerprint/control?engine=fingerprintjs` (no runtime
CDN). Runs as an independent **control** — full `components` (value + duration +
error) plus `visitorId` are stored under `control.fingerprintjs.*` and never feed
our verdicts. Local changes: none (byte-identical to the pinned upstream build).
