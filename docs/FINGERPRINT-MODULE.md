# Fingerprint diagnostic core — technical contract

The product flow compares a capture from ordinary Chrome (`plain`) with one from
the browser under test (`anti`). This public repository supplies the collector
core and validation primitives; the production panel, persistence, UI, and
exporters are separate and must implement the integration contract in
[`SERVER-INTEGRATION-HANDOFF.md`](SERVER-INTEGRATION-HANDOFF.md).

## Typed measurement envelope

Browser measurements use this collection-time shape:

```text
{ path, context, phase, status, valueType, value, error, meta }
```

The schema distinguishes successful values from unsupported, unavailable,
permission-related, blocked, timeout, error, and invalid results. Native special
values and structured objects are encoded into JSON-safe tagged forms. The
encoder is bounded; oversized/deep data needs a real server-side blob store before
it may be described as end-to-end lossless.

The schema/readiness code validates the encoded structure recursively. A server
must not reconstruct types later from display strings.

## Contexts and terminal state

The probe contains collectors for main frame, iframe variants, dedicated/shared/
module workers, service worker, audio worklet, cross-origin iframe, permissioned
probes, and network. A terminal `run-manifest` reports each expected context.

The server owns the canonical expected matrix. A browser-reported expectation
list cannot remove required contexts. Required contexts count as complete only at
terminal status `finished`; `fired` or request presence is not completion.

## Network

The capture source parses TLS ClientHello material used by JA3/JA4 and records
ordered HTTP fields. The current source target is `net-v6`, including HTTP/2
SETTINGS wire order/effective values and received pseudo-header order. Round 1
primes `Accept-CH`; only round 2 is the measurement and must be durably
acknowledged before the browser marks network `finished`.

Older fixture records are legacy data. Source support is not proof that the
production capture endpoint was redeployed or that a live browser produced a
valid `net-v6` record.

## Control engines

Four local artifacts may run as independent control measurements: ThumbmarkJS,
FingerprintJS OSS, FPScanner + fp-collect, and ClientJS. Their component values
are observations, not a safe/unsafe oracle. READY does, however, require every
configured engine to produce an internally consistent manifest bound to its exact
typed component rows. Static integrity/config tests do not prove runtime
no-egress; that requires a browser request ledger. See
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Readiness

`lib/fp-readiness.mjs` exposes strict side and pair validation. An integrating
server must provide persisted records plus its non-empty canonical expected
matrix. Readiness is blocked by malformed/unreadable records, missing contexts,
duplicate `(context,path)` keys, unexpected non-OK results, an incomplete
permissioned manifest, an incomplete network record, or missing control
manifests.

One authoritative result must feed the API, UI, Markdown, and Excel. An incomplete
snapshot may be exported for debugging but cannot be labeled READY.

## Comparator

The comparator is facts-first: it compares statuses/types/values, handles
duplicates explicitly, and applies a profile expectation only through the
registry. It must not label an unavailable measurement as leaked or masked, and
it must not silently keep the last duplicate value.

Derived output must prove:

```text
raw records = classified rows + excluded rows with explicit reasons
```

The exporter implementation is not in this repository, so that equation remains
an application-integration gate.

## Acceptance sequence

Review current source and run its tests, review/deploy the missing server
integration, run an automated paired browser smoke, then make one fresh human
plain/anti capture. Historical fixtures remain regression inputs, not proof of
current runtime behavior.
