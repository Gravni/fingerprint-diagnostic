# FingerprintJS OSS — vendored control engine

- Local file: `fp.v5.0.0.umd.min.js`
- Package: `@fingerprintjs/fingerprintjs` OSS (not Fingerprint Pro)
- Version: 5.0.0, identified in the artifact header
- Upstream: <https://github.com/fingerprintjs/fingerprintjs>
- Tag/commit: `v5.0.0` / `571a0a6136f78911d5fbcb91fdc3fe711ff25537`
- License: MIT; see the artifact header and `LICENSE`
- SHA-256: `d089678feb7cd84853cb5f0266d6568a3c751c3c204545b70c9013c29cc292f1`

The artifact is stored locally in this repository, while the application route
that serves it is outside this core-only tree. The browser probe calls
`FingerprintJS.load({ monitoring: false })`. A static regression test checks that
configuration and guards against a runtime CDN script source in the probe. It does
not replace a browser request-ledger test, so runtime no-egress remains an
integration gate.

The local file was verified byte-for-byte against `dist/fp.umd.min.js` in the
published npm tarball for `@fingerprintjs/fingerprintjs@5.0.0`. Its registry
integrity and release commit are recorded in `../vendor-lock.json`. A source
rebuild was not attempted. See `../../../THIRD_PARTY_NOTICES.md` and
`../vendor-lock.json` for the inventory and known provenance gaps.
