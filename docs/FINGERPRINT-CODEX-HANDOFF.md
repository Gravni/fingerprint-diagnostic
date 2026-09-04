# Fingerprint diagnostic — source-review handoff

This document describes the contents and review boundary of the current Git
checkout. It deliberately does not repeat an old bundle version, fixed assertion
count, or a historical “items closed” score.

## Review-branch changes Claude must preserve

- The browser template is rendered from one exact collector source; the source
  SHA-256 is part of every persisted identity and both sides of a pair.
- Same-origin real-URL iframe, cross-site iframe and Service Worker handshakes
  bind build, exact collector artifact, capture and fresh request/challenge data.
- Readiness owns a fixed 14-context matrix and build-owned leaf contracts. A
  browser manifest, control manifest or caller-provided matrix cannot lower it.
- AudioWorklet, Canvas, WebGL1/2, WebGPU, WebRTC, permissioned media/geo/device
  branches and the 21 FPScanner tests are independently reconciled server-side.
- Thumbmark/FingerprintJS derived IDs, the exact ClientJS getter set and all
  local sanity rows are mandatory; self-reported component counts are not enough.
- UA Client Hints use `formFactors` (plural) and the network round includes
  `Sec-CH-UA-Form-Factors` together with the previously required high-entropy
  hints.
- The capture service's source build is a closed-tree SHA-256 and a current
  network record also carries the observed peer address, runtime versions, raw
  ClientHello-derived vectors, H2 SETTINGS and pseudo-header order.

The private application must consume these contracts as written. Converting a
legacy row into v4.4 by filling missing identities or manifests with current
values would fabricate evidence and is forbidden.

## What can be reviewed here

- browser probe template: `assets/fingerprint-probe.html`;
- typed encoder, schema classifier, readiness validator, expectation registry,
  and comparator under `lib/`;
- TLS ClientHello/JA3/JA4 code and HTTP/2 observation code;
- standalone capture server;
- vendored control-engine artifacts, local hashes, and license material;
- executable unit/loopback tests and fixtures.

Run the tests from the repository root:

```bash
bash scripts/fp-test.sh
```

Use the totals printed by that exact run. No test result or build artifact is
committed here as evidence, and this document does not claim that an earlier log
still describes the checkout.

## What cannot be accepted from this repository alone

The production web application is absent. In particular, this repository does
not contain the panel routes, durable JSONL/database writer, `side-status`
endpoint, session-completion/UI logic, exporters, deployment configuration, or
browser-smoke harness. It therefore cannot establish any of the following:

- server-side integration of `validateSideCapture` / `validatePairedCapture`;
- durable acknowledgement of every browser context and the network record;
- consistency between raw JSONL, Markdown, Excel, and the admin UI;
- a real cross-site OOPIF process observation in the deployed environment;
- zero third-party egress at runtime;
- a production build ID covering the collector, capture server, panel writer,
  routes, UI, and exporter;
- a fresh plain/anti pair marked READY by the deployed validator.

Those are pending integration/evidence tasks, not implied by passing core unit
tests. The exact server checklist is in
[`SERVER-INTEGRATION-HANDOFF.md`](SERVER-INTEGRATION-HANDOFF.md).

## Current facts and review risks

| Area | Present in this checkout | Still required before use |
|---|---|---|
| Typed browser data | Probe and core encoder/schema code | Verify actual deployed probe is generated from the reviewed source |
| Readiness | Strict framework-independent validator | Wire it into the server and make its result authoritative for API/UI/export |
| Comparator | Facts-first rules and duplicate handling | Wire the same implementation into production and reconcile against raw |
| Network | ClientHello parsing and HTTP/2 observer/capture source | Pass tests, deploy the exact source, and observe a real `net-v6` round-2 record |
| Controls | Four local artifacts and static integrity/config tests | Runtime no-egress and successful engine manifests in the paired smoke |
| OOPIF | Probe/capture hooks | Cross-site origin and browser-process evidence in the deployed smoke |
| Provenance | Lockfile plus fail-closed capture ID over declared `lib/` + `scripts/` | Separate panel/route/UI/export IDs and a final product-level root identity |
| Licenses | Root license and several vendor license files/notices | Resolve the provenance/license-copy gaps listed in `THIRD_PARTY_NOTICES.md` |
| Export | Core comparator only | Production raw-union reconciliation and human-view checks; exporter source is absent |

## Acceptance order

1. Review the current Git diff and run all local tests.
2. Integrate the accepted core into the production server using the server
   handoff checklist.
3. Build and deploy from a clean, identified source revision.
4. Run an automated browser smoke for both `plain` and `anti`, checking responses,
   persistence, expected contexts, manifests, duplicate keys, network, controls,
   OOPIF evidence, and runtime egress.
5. Only after code acceptance, perform one fresh human paired plain/anti capture.
6. Mark the collector ready for employees only if the same server-side pair
   validator says READY and all raw/derived views reconcile.

Historical exported fixtures are regression inputs only. They are not evidence
that the current source or deployment satisfies these gates.
