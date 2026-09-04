# Browser Fingerprint Diagnostic (core)

This repository contains the reviewable, framework-independent core of a browser
fingerprint diagnostic. It collects typed browser measurements across execution
contexts, observes selected network-layer properties, and compares two captures.
Its intended uses are browser privacy research and anti-fingerprinting QA.

## Repository boundary

Included here:

- the browser probe template and four self-hosted control-engine artifacts;
- typed-value encoding, schema checks, readiness checks, comparison rules, and
  JA3/JA4 parsing;
- an HTTP/TLS capture server plus HTTP/2 SETTINGS/pseudo-header observation code;
- unit and loopback integration tests plus diagnostic fixtures;
- a GitHub Actions workflow that runs the same verification on macOS and Linux.

Not included here:

- the production panel, API routes, database writer, authentication, admin UI,
  Excel/Markdown exporters, deployment configuration, or a `side-status` route;
- Playwright/browser-smoke code or smoke artifacts;
- production capture results, secrets, certificates, or server logs.

Consequently, this repository alone cannot prove that the deployed application is
READY, that the server persisted every context, or that a real plain/anti pair
passes validation. The application integration requirements are listed in
[`docs/SERVER-INTEGRATION-HANDOFF.md`](docs/SERVER-INTEGRATION-HANDOFF.md).

## Source capabilities

- **Browser contexts:** the probe contains collectors for the main frame,
  dedicated/shared/module workers, audio worklet, iframe variants, service worker,
  a cross-origin iframe, permissioned probes, and a terminal run manifest. Which
  contexts actually run depends on the missing host application and deployment.
- **Network:** `scripts/capture-server.mjs` parses TLS ClientHello data for JA3/JA4
  inputs and contains source support for HTTP/2 SETTINGS and received pseudo-header
  order. This is not a claim that a production endpoint has been redeployed or
  observed in a live paired run.
- **Controls:** ThumbmarkJS, FingerprintJS OSS, FPScanner + fp-collect, and ClientJS
  artifacts are stored locally. They are independent observations, not inputs to a
  good/bad verdict. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- **Typed records:** measurements use
  `{path, context, phase, status, valueType, value, error, meta}`. The encoder is
  bounded and JSON-safe; any claim of fully lossless out-of-band blob persistence
  also depends on server code that is not in this repository.
- **Readiness:** `lib/fp-readiness.mjs` provides strict side and pair validation for
  an integrating server. Merely receiving the first JSONL record is never
  completion.

## Layout

```text
assets/      browser probe and vendored control-engine artifacts
lib/         encoding, schema, readiness, comparison, protocol parsers
scripts/     capture server and executable test files
tests/       diagnostic and legacy fixtures
docs/        technical scope, current plan, and integration handoff
```

## Verify the checked-out source

Use Node.js 22.14 or newer, matching the committed engine requirement and the
runtime used by the HTTP/2 integration tests.

```bash
bash scripts/fp-test.sh
```

The suite prints its own current assertion totals. Documentation intentionally
does not hard-code a count because it changes when regressions are added.

Install the two locked development dependencies without install scripts, then
run the complete verification command:

```bash
npm ci --ignore-scripts
npm run verify
```

`package-lock.json` pins the development dependency graph. TypeScript checks the
`.ts` sources and `.d.mts` public declarations. Runtime `.mjs` modules are
executed directly by the regression suite; this is not misrepresented as
`checkJs` coverage, and the absent production application is not typechecked.

The capture process computes its `captureBuild` at startup from the closed
`lib/` + `scripts/` executable inventory and refuses a mismatched configured ID.
That identifies this core checkout only; the absent panel, routes, UI, exporter,
and deployment still require their own component IDs. Each `net-v6` record also
stores `captureRuntime` (`node`, `v8`, `openssl`, `nghttp2`) because identical
source bytes running on different protocol stacks are not the same deployment
evidence. This is source/runtime attribution, not a claim that moving CI images
are bit-for-bit reproducible.

Some loopback network tests may require permission to bind a local port.

## Review status

Treat the current branch as source under review, not as an accepted release.
Before any employee collection, all local checks must pass, the missing server
integration must be reviewed and deployed, and one fresh plain/anti paired run
must pass the same server-side validator. See
[`docs/FINGERPRINT-V4-PLAN.md`](docs/FINGERPRINT-V4-PLAN.md).

## License

Repository-authored code is offered under [`LICENSE`](LICENSE). Files under
`assets/vendor/` retain their third-party terms. Local license evidence,
artifact hashes, and known provenance gaps are recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`assets/vendor/vendor-lock.json`](assets/vendor/vendor-lock.json).
