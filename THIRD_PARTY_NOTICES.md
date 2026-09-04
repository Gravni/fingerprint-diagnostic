# Third-party notices and provenance status

This repository stores third-party browser artifacts under `assets/vendor/` for
self-hosted control measurements. They remain separate from repository-authored
code and retain their upstream terms. This file records what is locally
verifiable; it is not legal advice or a claim that the final distribution audit
is complete.

## Local artifacts

| Component | Local artifact | SHA-256 | Local license evidence |
|---|---|---|---|
| ThumbmarkJS 1.11.0 | `assets/vendor/thumbmark/thumbmark-1.11.0.umd.js` | `5a12ec3d520aa95b7df0e54ab653c9c594cb8d89a430011c01cd1f8a5deb4bae` | `assets/vendor/thumbmark/LICENSE` (MIT) |
| FingerprintJS OSS 5.0.0 | `assets/vendor/fingerprintjs/fp.v5.0.0.umd.min.js` | `d089678feb7cd84853cb5f0266d6568a3c751c3c204545b70c9013c29cc292f1` | artifact header and `assets/vendor/fingerprintjs/LICENSE` (MIT) |
| FPScanner + fp-collect bundle | `assets/vendor/fpscanner/fpscanner.bundle.js` | `8414f22e6f2466dae55c37b8c8375344679f9469f58590a333d00a16bdc6982c` | FPScanner, fpcollect and ua-parser-js MIT texts plus `NOTICE` in `assets/vendor/fpscanner/` |
| ClientJS 0.2.1 | `assets/vendor/clientjs/clientjs-0.2.1.base.min.js` | `5077379fc482d99daeceafb9b63cac07e24f29c6dfba28c445baf3f2ce4d9f22` | Apache-2.0, modification `NOTICE`, and embedded MIT notices in `assets/vendor/clientjs/` |

The artifact digests above match the files in this checkout. The static vendor
test reads the canonical artifact/source pins from `vendor-lock.json`, verifies
the enumerated license files are present and non-empty, checks selected collector
configuration, and performs a limited scan for common network-call APIs. It is not
a runtime no-egress test and does not prove upstream identity or reproducibility.

## Upstream references and local configuration

- **ThumbmarkJS:** <https://github.com/thumbmarkjs/thumbmarkjs>, tag `v1.11.0`,
  commit `0d14734b667a659e3f99a035c0226fabfc75f8f3`. The local UMD is byte-identical
  to the published npm `1.11.0` tarball member. The local probe
  calls `setOption('logging', false)`. The artifact is stored locally here; the
  missing integrating application must supply its self-hosted route. The vendored
  file itself contains upstream network-capable code/defaults, so only a browser
  request ledger can prove no runtime egress for a particular build.
- **FingerprintJS OSS:** <https://github.com/fingerprintjs/fingerprintjs>, tag
  `v5.0.0`, commit `571a0a6136f78911d5fbcb91fdc3fe711ff25537`. The artifact
  is byte-identical to the published npm `5.0.0` tarball member and identifies
  itself as MIT in its header. The probe calls
  `FingerprintJS.load({ monitoring: false })`. The artifact is local to this
  tree, but the self-hosted application route is absent. Runtime no-egress remains
  an integration-smoke requirement.
- **FPScanner:** <https://github.com/antoinevastel/fpscanner>. The retained source
  matches `fpscanner@0.1.5` from npm (`gitHead` `cf1d0c1cbe53bba244c14862cb8c30ec92176fb3`).
- **fp-collect:** <https://github.com/antoinevastel/fp-collect>. The local bundle
  retained source matches `fpcollect@1.0.5` from npm (`gitHead`
  `7a49625651a61c1b8b9a6114b841fe74c7ec3b31`).
- **ua-parser-js:** <https://github.com/faisalman/ua-parser-js>. The FPScanner
  input `ua-parser-0.7.40.js` is byte-identical to the npm `0.7.40` source and
  contains its MIT header. The ClientJS artifact contains a v0.7.41 marker.
  These facts do not by themselves reproduce either assembled bundle.
- **ClientJS:** <https://github.com/jackspirou/clientjs>. The local artifact is
  distributed with an Apache-2.0 license file. It is a locally rebuilt artifact,
  not an untouched upstream release file.

### Components embedded in the rebuilt ClientJS base bundle

The declared ClientJS commit's `src/client.base.js` directly imports
`globalthis/polyfill`, `murmurhash-js/murmurhash3_gc`, `ua-parser-js`, and its
vendored `fontdetect` source. The declared commit's lock resolves the transitive
globalthis chain. ua-parser-js was intentionally replaced during the local rebuild.

| Component | Version | License | Recorded basis |
|---|---:|---|---|
| globalthis | 1.0.2 | MIT | direct ClientJS import; version in declared commit lock |
| define-properties | 1.1.3 | MIT | globalthis runtime dependency in declared commit lock |
| object-keys | 1.1.1 | MIT | define-properties runtime dependency in declared commit lock |
| murmurhash-js | 1.0.0 | MIT | direct ClientJS import; version in declared commit lock |
| ua-parser-js | 0.7.41 | MIT | locally substituted input; version marker observed in artifact |
| fontdetect | 0.3 | Apache-2.0 | ClientJS vendored source header (Lalit Patel) |

The exact machine-readable inventory and upstream references live in
`assets/vendor/vendor-lock.json`; the table here is explanatory, not a second hash
lock. `inherits` 2.0.4 is an upstream package dependency but is not reachable from
the ClientJS base entry and is not identified as embedded in this artifact.

The four control engines write independent observations. Repository verdict code
must not use a control engine as an oracle for “safe” or “unsafe.”

## Repository protocol implementations

`lib/ja4.ts` is repository code implementing the published JA4/JA3 formats. The
repository does not declare copied upstream JA4 or JA3 implementation source.
Specifications/upstream projects referenced by the code and tests:

- JA4: <https://github.com/FoxIO-LLC/ja4>
- JA3: <https://github.com/salesforce/ja3>

Any attribution required by copied material introduced later must be reviewed at
that time; this note is not a substitute for retaining its license.

## Provenance and packaging gaps

The following must be resolved or explicitly accepted before claiming a complete,
reproducible third-party compliance package:

- ThumbmarkJS/FingerprintJS release provenance and FPScanner/fpcollect/ua-parser
  source provenance are now pinned to published npm tarballs. Source-level
  byte-for-byte rebuilds were not performed.
- The FPScanner bundle still lacks the exact retained entry file, package lock and
  build workspace required to reproduce its output digest, although all three
  retained third-party source inputs and their license texts are now verified.
- ClientJS has a declared upstream commit/build recipe in `vendor-lock.json`, but
  the source checkout, patched lockfile, webpack configuration, and build log
  needed to reproduce the shipped digest are absent.
- The ClientJS artifact is a modified Apache-2.0 object (ua-parser-js was
  substituted). A prominent adjacent `NOTICE` and all identified embedded MIT
  notices are now present, but the minified JavaScript itself has no modification
  header. Confirm the final packaging treatment of Apache-2.0 section 4(b) before
  distribution.
- The core has a committed npm lock, but the absent final application still lacks
  a reviewed dependency lock, generated SBOM, vulnerability scan, and
  transitive-license report in this repository.

Keep the per-component license files beside all shipped artifacts. Do not delete
third-party notices to make the tree look cleaner; close the provenance gaps with
source pins and exact build evidence.
