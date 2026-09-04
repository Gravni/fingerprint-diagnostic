# SBOM — source-review-v4.3 (buildId c9d282392eb5f95d)

## Vendored control engines (self-hosted, pinned, telemetry off)
See THIRD_PARTY_NOTICES.md for full SHA-256 pins and licences.
- ThumbmarkJS 1.11.0 — MIT — assets/vendor/thumbmark/
- FingerprintJS OSS 5.0.0 — MIT — assets/vendor/fingerprintjs/
(Control engines #3/#4 — FPScanner+fp-collect MIT, ClientJS 0.2.1 Apache-2.0 —
 are being vendored; see docs/FINGERPRINT-V4-PLAN.md #13 for exact pins.)

## Build/test tooling (devDependencies)
- typescript ^5.6.0 — Apache-2.0
- @types/node ^22.0.0 — MIT

## Runtime
- Node.js built-ins only for the pure core (crypto/fs/path/url/net/https/tls).
- The full server module (lib/fingerprint.ts) + routes use Next.js/React (shipped
  as source; not part of the standalone build).
