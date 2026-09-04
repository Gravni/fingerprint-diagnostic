# Fingerprint diagnostic — current acceptance plan

This plan replaces the accumulated v4.1/v4.2/v4.3 status narrative. Git history
is the record of old claims. A checkbox here means a current, reviewable gate; it
does not mean “code once existed in a separate server bundle.”

## Definition of ready

The collector is ready for one-time employee measurements only when all four
gates below are satisfied for the same identified build:

1. **Core accepted:** source review is complete and every checked-in test passes.
2. **Application accepted:** the production panel uses the reviewed schema,
   readiness, comparison, persistence, and export logic without weaker parallel
   implementations.
3. **Automated paired smoke accepted:** a real browser completes both `plain` and
   `anti`; the server confirms persistence, exact context coverage, network,
   controls, and terminal manifests; no duplicate keys or unexpected egress.
4. **Fresh paired capture accepted:** after code acceptance, one new human
   plain/anti pair returns READY from the same server-side validator and every
   derived view reconciles with raw data.

No account outcome, historical fixture, fixed test count, screenshot, or old
archive substitutes for these gates.

## Gate A — core source

- [ ] Review the current diff in Git rather than trusting a handoff summary.
- [ ] `bash scripts/fp-test.sh` passes on the exact revision to be deployed.
- [ ] Schema validation rejects empty server expectations, malformed typed values,
      duplicate `(context,path)` keys, unreadable records, and unapproved non-OK
      statuses.
- [ ] `validateSideCapture` requires the server's canonical context matrix, the
      terminal run manifest, permissioned completion, one current network record,
      and all expected control-engine manifests.
- [ ] `validatePairedCapture` requires both sides to pass the same side validator.
- [ ] Comparator behavior is duplicate-safe and every emitted path has an
      expectation rule or an explicit exclusion reason.
- [ ] Network `net-v6` tests cover strict ClientHello parsing, JA3/JA4 edge cases,
      HTTP/2 client-preface/SETTINGS capture, and received pseudo-header order.
- [ ] Documentation and declarations match the actual files. Test totals remain
      runtime output, not hard-coded release evidence.

## Gate B — production application integration

This repository does not include the application, so every item remains pending
until the server diff is supplied and reviewed.

- [ ] Use one canonical server-owned expected-context matrix for a build. The
      browser manifest may report what ran but may not shrink server expectations.
- [ ] Persist browser records, network, and the terminal manifest before reporting
      side completion.
- [ ] Include and deploy the `side-status` route; have it call the reviewed strict
      readiness validator.
- [ ] Remove any first-line/count-based `sessionComplete` behavior.
- [ ] Accept only `finished` for required terminal contexts; `fired` is not an
      acknowledgement.
- [ ] Store one final `net-v6` record: round 1 primes Client Hints and is not the
      measurement; round 2 is acknowledged only after durable server persistence.
- [ ] Use the same readiness result in API, UI, Markdown, Excel, and automation.
      No competing “VALID” badge may disagree with NOT READY.
- [ ] Reconcile raw union as classified rows plus explicitly excluded rows with a
      reason. Do not silently collapse duplicate keys or omitted values.
- [ ] Compute runtime build IDs from a complete, declared executable-file
      inventory. Missing inputs fail the build; placeholders such as `unknown` do
      not pass readiness.
- [ ] Review the concrete integration against
      [`SERVER-INTEGRATION-HANDOFF.md`](SERVER-INTEGRATION-HANDOFF.md).

## Gate C — automated paired browser evidence

- [ ] Run the exact deployed build for both `plain` and `anti`.
- [ ] Assert all browser requests are 2xx and all expected records are durably
      stored, not merely sent.
- [ ] Assert the exact canonical context matrix, terminal `finished` statuses, no
      duplicate `(context,path)` keys, complete permissioned phase, and all four
      engine manifests.
- [ ] Assert the network side is `net-v6`, negotiated HTTP/2, and contains the
      final round-2 record with SETTINGS and pseudo-header order.
- [ ] Prove the OOPIF uses a different registrable site and capture browser/CDP
      process or target evidence.
- [ ] Record a complete request ledger and an explicit quiet window; classify any
      third-party request rather than inferring no egress from static source.
- [ ] Save artifacts tied to the same commit/build IDs. Do not copy stale smoke
      files into a new bundle.

## Gate D — final paired human capture

- [ ] Run once, only after Gates A–C pass.
- [ ] Use the same machine, collector build, and collection procedure for plain
      Chrome and the browser under test.
- [ ] Complete passive and permissioned phases and internal repeats.
- [ ] Require the server-side paired validator to return READY.
- [ ] Verify raw JSONL, network raw, report, Excel, manifests, hashes, and UI all
      describe the same session and reconcile numerically.

## Separate workstreams that are not closed by core tests

- **Provenance:** this core now has a committed dependency lock and the capture
  process computes a fail-closed ID over the declared `lib/` + `scripts/` tree.
  The missing panel/routes/UI/exporter still need separate component IDs and a
  final product-level root identity.
- **License packaging:** local artifacts/hashes are inventoried, but some vendored
  transitive source provenance and separate license copies remain incomplete; see
  `THIRD_PARTY_NOTICES.md`.
- **Deployment:** no VPS or panel state is evidence until its source revision and
  runtime build IDs match the accepted Git revision.
- **Product quality:** READY means the diagnostic capture is complete and
  internally consistent. It does not by itself prove browser anonymity or predict
  a third party's account-risk decision.
