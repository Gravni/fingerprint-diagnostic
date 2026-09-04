# Network fingerprint capture — deployment boundary

Page JavaScript cannot observe the TLS ClientHello or the initial HTTP/2 SETTINGS
frame. Those values are visible only at a capture endpoint that terminates the
browser's TLS connection directly. A CDN or reverse proxy that terminates TLS
first changes the observed client to that intermediary.

## Source present in this repository

- `lib/ja4.ts` parses ClientHello data and computes JA3/JA4-format values.
- `lib/h2-observe.mjs` observes the HTTP/2 client preface and first SETTINGS
  frame, then preserves the bytes for Node's HTTP/2 stack.
- `scripts/capture-server.mjs` is the standalone capture process.

The production panel routes that mint tokens, persist network results, report
side readiness, and export data are not in this repository. Their existence or
deployment must not be inferred from the capture source.

## Required topology

Use a dedicated hostname whose DNS points directly to the capture server and a
certificate valid for that hostname. Keep the panel behind its normal ingress if
desired, but ensure the browser-to-capture TLS connection is not terminated by a
third party first.

Required configuration values are read by `scripts/capture-server.mjs`; inspect
the current source before deployment rather than copying an old command from this
document. At minimum, provision the certificate/key, shared capture secret, panel
callback URL, and listening port without committing secrets to Git.

## `net-v6` request lifecycle

The integration must mint one token and make exactly two logical requests per
side with that same token:

1. round 1 establishes the `Accept-CH` policy and is not persisted as the final
   measurement;
2. round 2 consumes the token, carries the advertised hints, and becomes the
   single final `net-v6`
   record;
3. the capture server waits for durable panel persistence before returning
   success;
4. only that successful response lets the browser mark network `finished`.

Do not send `Critical-CH` on the probe or capture responses. It may introduce an
implicit browser retry outside the explicit two-request protocol. Retries must be
idempotent or explicitly represented; they may not silently create duplicate
network records.

For HTTP/2, the final record is expected to include the negotiated protocol, the
first SETTINGS payload/order/effective values, its hash, and received
pseudo-header order. It also includes the socket-observed peer IP/family, exact
TLS termination marker, the source-tree `captureBuild`, and the executing Node,
V8, OpenSSL and nghttp2 versions under `captureRuntime`. Node's `rawHeaders` supplies request-header receive order;
the custom observer is only for the initial SETTINGS frame.

## Verification before production use

1. Run `bash scripts/fp-test.sh` on the exact Git revision to deploy. Some network
   tests bind a loopback port.
2. Integrate and review the panel callbacks and strict `side-status` route using
   `SERVER-INTEGRATION-HANDOFF.md`.
3. Build and deploy with real component build IDs, not `unknown`, a schema label,
   or an old archive hash.
4. Run a real browser capture and inspect the persisted round-2 record. Confirm
   `net-v6`, HTTP/2, SETTINGS, pseudo-header order, typed TLS/header vectors, and
   the expected build IDs.
5. Run both plain and anti in the automated paired smoke before the final human
   capture.

A successful local parser test proves protocol logic only. It does not prove DNS,
certificate, ingress, panel persistence, deployment revision, or live browser
behavior.
