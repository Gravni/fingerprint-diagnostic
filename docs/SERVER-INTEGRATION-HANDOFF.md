# Server integration handoff for Claude

The public Git repository is **core-only**. Do not report this work as deployed or
end-to-end complete until the private panel/server change is supplied for review.
Use the current Git revision as the source of truth; do not copy logic from an old
v4.x archive.

This review branch adds a non-optional `collectorArtifactSha256` identity field.
Claude must thread it through the build response, every persisted record, the
terminal manifest, both bound iframe handshakes, the Service Worker URL/request/
response, `SideCaptureInput`, and the pair validator. A build label alone is no
longer sufficient. Do not adapt old stored captures by inventing this field;
classify them as legacy evidence.

## 1. Make strict readiness authoritative

- Import the reviewed `validateSideCapture` and `validatePairedCapture` from
  `lib/fp-readiness.mjs` (or package the exact accepted file into the server).
- Use the exported `DEFAULT_EXPECTED_CONTEXTS` as the exact canonical matrix for
  this collector build: **14 data contexts**. `run-manifest` is a separate,
  exactly-once terminal record and must not be inserted into
  `serverExpectedContexts`; the validator deliberately rejects that mismatch.
  A future matrix change requires a reviewed collector/validator contract change,
  not a database or browser-side toggle.
- Do not derive the canonical matrix from the browser's `manifest.expected`.
  Compare the browser report with the server matrix and reject omissions or
  additions that violate the contract.
- Parse every persisted JSONL line. An unreadable line, duplicate outer context,
  duplicate `(context,path)`, missing required context, malformed typed value, or
  disallowed non-OK result must make that side NOT READY.
- Construct `SideCaptureInput.collectorArtifactSha256` from the server-owned
  immutable deployment descriptor. It is a lowercase 64-hex SHA-256 of the exact
  collector source bytes. Never learn it from one of the records being graded.
- A pair is READY only when both sides pass the same strict side validator. Do not
  keep a weaker legacy validator in UI/export code.

## 2. Fix lifecycle and acknowledgement

- Include a real `/api/fingerprint/side-status` implementation in the reviewed
  server source and deployment. It is absent from this public repository.
- Remove any `sessionComplete`, `complete`, or UI-unlock condition based on the
  first record, `lineCount > 0`, presence of a file, or receipt of an HTTP request.
- Persist each context durably before returning its successful acknowledgement.
- Store/upsert a context idempotently by the server-derived
  `(pairKey, captureKey, environment, collectorBuild,
  collectorArtifactSha256, context)` identity. A lost
  HTTP response followed by a retry must return the prior durable result, not
  append a duplicate context. Never trust those identity fields solely because
  they appeared in the browser body; bind them to the authenticated session and
  URL/token record.
- Persist the terminal `run-manifest` last. For each required context the terminal
  status must be exactly `finished`; `fired`, `sent`, or merely present is not an
  acknowledgement.
- The side-status route must run strict validation against persisted data and
  return its structured reasons. The browser may show “готово” only after that
  route confirms side readiness for the same session/environment/build.
- Handle failed fetches and non-2xx replies as failures. Do not resolve them as a
  successful send or silently convert them to terminal success.
- Configure the capture process with an explicit `PANEL_FETCH_TIMEOUT_MS`. Every
  build/source/persistence request is aborted at that deadline and when the
  downstream browser request closes. The network-result writer receives both
  `x-capture-deadline` and a deterministic `x-idempotency-key` (also repeated in
  the `delivery` object). Before committing, reject expired deadlines and make
  the idempotency key unique. A timed-out request must not become a late write.
- Once `permissioned` and `run-manifest` have been acknowledged, a UI retry only
  polls `side-status`; it must not prompt again or POST either context again.

## 2a. Render one executable probe artifact

- Never serve `assets/fingerprint-probe.html` directly. It is a fail-closed
  template containing mandatory encoder/build markers.
- Read that template and `lib/fp-encode.mjs`, compute the browser-component build
  from the reviewed source inputs (not from the final self-labelled output), then
  call `renderFingerprintProbe()` from `lib/fp-probe-artifact.mjs` exactly once
  for that build.
- Serve `result.html` as the main fingerprint page and
  `result.collectorSource` from `/fingerprint/collector`. Publish
  `result.collectorArtifactSha256` as
  `browserCollectorArtifactSha256`; keep `result.artifactSha256` separately for
  the exact main-page bytes. Do not extract or maintain a second hand-written
  collector copy.
- Cache only the immutable tuple
  `(browserCollectorBuild, html, artifactSha256, collectorSource,
  collectorArtifactSha256)`. Fail startup/build if either placeholder remains.
- Add route-level tests that fetch the actual HTTP responses, assert no marker is
  present, recompute both hashes from received bytes, and parse both scripts.
  Unit-testing the renderer without testing the serving routes is insufficient.
- A `collect` query override, if retained for local development, may resolve only
  to the current origin. Reject absolute/canonical URLs whose origin differs;
  never POST the full capture to an arbitrary URL supplied in a link.
- Implement a separate authenticated
  `/api/fingerprint/collector-descriptor` route for the capture service. It
  returns only immutable artifact facts
  `{browserCollectorBuild, browserCollectorArtifactSha256}` and contains no
  session/challenge/OOPIF state. The reviewed capture service uses this exact
  route plus `/fingerprint/collector`, authenticating both requests with
  `x-capture-secret`. Do not alias it to the capture-specific build route below.

## 2b. Implement this exact route inventory

The paths below are separate contracts. Do not combine routes merely because two
of them currently return related build data. Every successful response is
`Cache-Control: no-store` unless it serves an immutable, content-addressed vendor
artifact; every JSON route sets `application/json`, every executable route sets
the appropriate HTML or JavaScript content type.

| Route | Caller and required result | Binding / authorization |
|---|---|---|
| `GET /fingerprint?env&sid` | Employee browser; return the one rendered `result.html` | Authenticated employee session; exact `env`, server-owned pair and current browser build |
| `GET /api/fingerprint/build?env&sid` | Main probe; return browser build, collector artifact SHA-256, SW challenge and complete OOPIF expectation | Same authenticated capture; response identity is server-derived, never copied from request JSON |
| `POST /collect` | Main probe; durably persist one browser context and acknowledge only after commit | Authenticated capture plus exact `(pair,capture,env,build,context)`; idempotent on that key |
| `GET /api/fingerprint/side-status?env&sid` | Main probe; return the canonical `validateSideCapture` result | Same capture/build; run validation over persisted rows, not request counters |
| `GET /fingerprint/control?engine&build&sha256` | Browser control loader; return exactly one locally vendored artifact | `engine` is an allowlisted ID; `build` is current; `sha256` is the reviewed vendor-lock digest; reject mismatches and send immutable bytes with the same digest/SRI |
| `GET /fingerprint/frame?...bound fields...` | Same-origin real-URL child; return `renderBoundChildProbe(...)` | Validate all eight bound-child query fields described below against the current collector tuple and authenticated capture |
| `GET /fingerprint/sw?build&artifact&capture&challenge` | Browser; return `renderServiceWorkerProbe(...)` JavaScript | Exact current collector build + collector artifact SHA-256, server-owned capture key and one-time challenge; unique scope; no cache |
| `GET /api/fingerprint/xprobe-url` | Main probe; return base cross-site `/xprobe` URL plus current `configurationId` | Same capture and the exact OOPIF configuration returned by `/api/fingerprint/build`; do not return an arbitrary caller URL |
| `GET /api/fingerprint/net-token?env&sid&round=2` | Main probe; mint/retrieve the token used for both network rounds | Same capture; token is one-time/idempotent, expiry-bound and resolves server-side to the exact side/build |
| `GET /api/fingerprint/collector-descriptor` | Capture process; return `{browserCollectorBuild,browserCollectorArtifactSha256}` only | `x-capture-secret`; immutable deployment facts, no employee/session state |
| `GET /fingerprint/collector` | Capture process; return the exact `result.collectorSource` bytes | `x-capture-secret`; hash must equal the descriptor; never serve a stale fallback |
| `GET https://<capture>/xprobe?...bound fields...` | Cross-site iframe; return `renderBoundChildProbe(...)` | Exact current collector tuple, allowlisted parent origin and all bound-child fields; CSP `frame-ancestors` from the allowlist |
| `GET https://<capture>/?token&round=1|2` | Browser network probe; round 1 primes hints, round 2 persists one `net-v6` row | Direct TLS termination; exact token; round 2 waits for panel durability |
| `POST /api/fingerprint/net-result` | Capture process; persist the final network record | `x-capture-secret`, deadline and idempotency key; recompute server-owned outer identity before commit |

The bound real-URL child query is exactly:

`fpVersion=1`, `fpContext`, `fpBuild`, `fpArtifact`, `fpCapture`, `fpRequest`,
`fpParent`, and `fpAck`. Reject missing, duplicate or additional keys. The
same-origin route accepts only `iframe-url`; the capture route accepts only
`cross-origin-iframe`. `fpRequest` is a fresh 128-bit-or-stronger URL-safe value.
`fpAck` is the SHA-256 returned/recomputed by `renderBoundChildProbe` over the
canonical build/artifact/capture/context/request/parent binding. The child posts
only `{__fpBoundChild:1,binding,payload}` to the exact parent origin; the parent
checks `event.source`, `event.origin`, every binding field and
`payload._boundChild` before POSTing it. A legacy bare `/fingerprint/frame`, bare
`/xprobe`, or `{__fp|__fpx,m}` message must fail closed.

Add route integration tests that fetch every executable response, recompute its
declared hash, verify build/capture binding and test stale-build, altered-hash,
duplicate-query, wrong-parent, timeout and failed-persistence cases. Unit tests
of the render helpers do not substitute for these server-route tests.

## 3. Integrate the `net-v6` capture contract

- Deploy the reviewed `scripts/capture-server.mjs`, `lib/ja4.ts`, and
  `lib/h2-observe.mjs` together. Do not mix a new schema with an old capture
  process.
- Negotiate HTTP/2 and capture the first client SETTINGS frame before handing the
  same bytes back to Node's HTTP/2 stack. Preserve SETTINGS wire order, duplicate
  and unknown IDs, effective values, and a payload hash.
- Read pseudo-header order from the request's received `rawHeaders`; do not invent
  an HPACK decoder solely to reconstruct information Node already exposes.
- Use the two-request Client-Hints flow exactly once per side:

  1. mint one one-time token and reuse it for both requests;
  2. round 1 only establishes the `Accept-CH` policy and is not stored as the
     measurement;
  3. round 2 consumes that token and is the single final `net-v6` record;
  4. the capture endpoint waits for the panel writer's durable acknowledgement
     before returning success;
  5. only that successful response may mark the browser's network context
     `finished`.

- Do not send `Critical-CH` on the probe or capture responses. It may introduce
  an implicit browser retry outside the explicit two-request protocol.
- The current network validator must require the final schema version, HTTP/2,
  SETTINGS, pseudo-header order, typed TLS/header vectors, parser version, and a
  real capture build ID. Treat older `net-v4`/`net-v5` records as legacy evidence,
  never CURRENT.
- Pass the server-owned exact build ID of the deployed capture executable as
  `expectedNetworkBuild` to both side validators. Obtain it from the same closed
  executable-tree build step / checked `CAPTURE_BUILD` deployment value; never
  learn it from the incoming network record. A valid `net-v6` record from a
  different or previous capture build is NOT READY even when plain and anti
  happen to match each other.
- Store exactly one final network record per `(session, environment)`. A retry must
  be idempotent or explicitly versioned; it must not create a duplicate silently.
- Resolve the one-time network token to the same server-owned pair/capture/build
  identity and stamp that identity onto the outer `network` record in the writer.
  The capture endpoint cannot infer it from TLS alone.

### Required UA-CH headers on the top-level probe response

Chrome sends high-entropy UA Client Hints to a cross-origin capture endpoint only
after the top-level document opts in and delegates them. Sending `Accept-CH` only
on the capture response is not sufficient. The response that serves the main
probe must request the complete set and delegate every cross-origin hint to the
exact capture origin, for example:

```http
Accept-CH: Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors
Permissions-Policy: ch-ua-platform-version=(self "https://capture.example"), ch-ua-arch=(self "https://capture.example"), ch-ua-bitness=(self "https://capture.example"), ch-ua-model=(self "https://capture.example"), ch-ua-full-version-list=(self "https://capture.example"), ch-ua-wow64=(self "https://capture.example"), ch-ua-form-factors=(self "https://capture.example")
```

Generate this header from the same exact configured capture origin; do not paste
the example hostname. Assert in a real Chrome smoke that round 2 contains all
required fields and that flat values exactly equal the ordered typed headers.
This follows the [Chrome UA-CH cross-origin guidance](https://developer.chrome.com/docs/privacy-security/user-agent-client-hints#hint_scope_and_cross-origin_requests)
and the [UA Client Hints delegation model](https://wicg.github.io/ua-client-hints/#delegation).

## 3a. Configure and bind the cross-site collector

- `PANEL_PUBLIC_ORIGINS` is mandatory on the capture process. Set it to the
  comma-separated exact HTTP(S) origins that may embed `/xprobe`, for example
  `https://fingerprint.company.tld`. Paths, wildcards, credentials and sample values
  are rejected at startup. The `frame-ancestors` CSP is built only from this
  validated list.
- `/api/fingerprint/build?env=<plain|anti>&sid=<pairKey>` is capture-specific and
  distinct from `/api/fingerprint/collector-descriptor`.
  Authenticate the request, derive `captureKey = sid + ":" + env` on the server,
  and return two independent 64-character lowercase SHA-256 values:
  `browserCollectorBuild` for the collector component build and
  `browserCollectorArtifactSha256` for the exact bytes returned by
  `/fingerprint/collector`.
- The same response must return a URL-safe, expiry-bound, at-least-128-bit
  `serviceWorkerChallenge` and a `crossOriginProbe` object with
  `parentOrigin`, `childOrigin`, server-resolved `registrableParentSite` and
  `registrableChildSite`, `configurationId`, `processEvidence`,
  `processEvidenceSha256`, and `processEvidenceBuild`.
- Keep both endpoints authentication/network-restricted as appropriate for the
  deployment. The capture process refuses malformed build metadata, verifies the
  source bytes against the artifact hash, and never serves a cached collector if
  the build endpoint is unavailable or invalid.
- Compute registrable sites with a maintained Public Suffix List implementation
  on the server. Do not accept `parentSite`/`childSite` as browser assertions and
  do not approximate eTLD+1 by splitting on dots.
- Persist the automated browser/CDP process evidence artifact itself. This is
  **deployment/build evidence**, produced once by the automated smoke for the
  exact collector build and cross-site configuration; a manual employee tab
  cannot read renderer process IDs and must not require a per-capture CDP run.
  At minimum the artifact contains `collectorBuild`, `configurationId`, both
  origins, both registrable sites, and distinct non-empty `parentProcessId` and
  `childProcessId`. Compute its SHA-256 over UTF-8 JSON after recursively sorting
  object keys (array order is preserved). Bind the accepted digest/build to each
  capture server-side; browser records echo only that binding plus their own
  verified `event.origin`. A browser-supplied arbitrary 64-hex string or process
  ID is not evidence.

## 3b. Bind and isolate the Service Worker probe

- `/fingerprint/sw` must generate a script bound to the requested exact
  `collectorBuild`, `collectorArtifactSha256`, `captureKey`, and
  `serviceWorkerChallenge`. Its registration scope must
  be unique to that capture so two tabs cannot share realm-global collector state
  or unregister one another's worker.
- The message is structured and repeats those expected values, including the
  exact collector artifact SHA-256. The worker must
  reject a mismatch and return the same values in `_serviceWorker`; the browser
  must verify them before POSTing the context. Do not prefer an unrelated existing
  `navigator.serviceWorker.controller` over the just-registered worker.
- The response `_serviceWorker` object must echo the build, collector artifact
  SHA-256, capture key,
  `serviceWorkerChallenge`, handshake version, request ID, exact script URL and
  scope. Its `acknowledgementSha256` is the same canonical SHA-256 construction
  over `{context:"service-worker", collectorBuild, collectorArtifactSha256,
  captureKey, challenge:serviceWorkerChallenge}`; the server recomputes it
  during readiness.
- Disable HTTP cache for the worker update path, wait for the exact worker to
  activate, serialize collection messages inside that worker, close message ports,
  and unregister only the registration owned by that page.

## 4. Supply real provenance

- Keep the reviewed capture server's runtime-computed `captureBuild`; do not
  override it with a label. Its closed inventory currently covers this core's
  `lib/` + `scripts/` tree and startup fails on missing/unlisted inputs.
- Preserve the `captureRuntime` object stamped by the process (`node`, `v8`,
  `openssl`, `nghttp2`) and require it in `net-v6`. `captureBuild` identifies
  source bytes; runtime protocol versions are separate execution inputs. Pin a
  deployment image if the final release needs stronger reproducibility.
- Generate build IDs from an explicit, complete list of executable inputs for the
  browser collector, cross-origin collector, capture process, panel writer,
  routes, validator/comparator, UI/exporter, and vendor manifest.
- Fail the build when a declared input is missing or an executable input is not in
  the inventory. Do not fall back to `unknown`, a short label such as `net-v6`, an
  old bundle hash, or a hand-written version string.
- Stamp component build IDs into the persisted raw/manifest data and include the
  Git commit used to build the deployment. Validation must reject missing or
  contradictory IDs.
- The public core now has a root npm lock. Commit the private application's own
  dependency lock and build from it before describing the whole product build as
  reproducible.
- Configure `CERT_FILE` and `KEY_FILE` as an inseparable production pair. The
  reviewed capture process permits an ephemeral self-signed certificate only with
  `ALLOW_SELF_SIGNED_FOR_TESTS=1`. Every hostname listed in `TLS_DOMAINS` must have
  a readable certificate at startup; a warning plus fallback certificate is not
  an acceptable production state.

## 5. Keep every view on the same facts

- Production comparison must use the reviewed comparator. It must not collapse
  duplicate `(context,path)` entries with last-write-wins behavior.
- Markdown, Excel, admin UI, and API must all use the same readiness object and
  the same classified rows. There must be no separate green “VALID” state beside
  NOT READY.
- Prove `raw union = classified + excluded(with explicit reason)` using the raw
  pre-collapse records. Include browser and network records in the equation.
- Keep exact coordinates in the raw JSONL according to the operator's decision;
  the shareable Excel may show the bucket and plain↔anti distance instead.

## 6. Evidence to return for review

Return one Git commit/diff containing the server integration, not a prose-only
completion report. Include:

- the panel/API/persistence/export/UI sources changed above;
- the canonical expected matrix and route tests;
- tests proving first-line completion is impossible, `fired` is rejected,
  browser expectations cannot shrink the matrix, failed persistence blocks
  readiness, and only one final network record is stored;
- a clean build/test log generated from that commit;
- provenance/build manifests produced by the build, without secrets.

After that code is accepted, run an automated paired browser smoke. It must cover
both environments, response codes, durable persistence, exact contexts, controls,
network, OOPIF/process evidence, duplicates, console/page failures, and a quiet
no-egress window.

Only after the automated smoke passes should the operator perform the one final
fresh plain/anti capture. Do not ask for repeated employee runs to compensate for
unfinished code or missing server evidence.
