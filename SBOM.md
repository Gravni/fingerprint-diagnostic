# Source inventory / SBOM status

This file inventories artifacts physically present in this Git repository. It is
not a generated CycloneDX/SPDX document and does not describe the absent production
panel or its dependency tree.

## Vendored browser artifacts

| Artifact | Declared version | Local path | License evidence in repository |
|---|---:|---|---|
| ThumbmarkJS | 1.11.0 | `assets/vendor/thumbmark/thumbmark-1.11.0.umd.js` | `assets/vendor/thumbmark/LICENSE` (MIT) |
| FingerprintJS OSS | 5.0.0 | `assets/vendor/fingerprintjs/fp.v5.0.0.umd.min.js` | file header + `assets/vendor/fingerprintjs/LICENSE` (MIT) |
| FPScanner + fp-collect bundle | 0.1.5 / 1.0.5 | `assets/vendor/fpscanner/fpscanner.bundle.js` | FPScanner, fpcollect and ua-parser-js MIT texts plus `NOTICE` are present |
| ClientJS | 0.2.1 | `assets/vendor/clientjs/clientjs-0.2.1.base.min.js` | Apache-2.0, modification `NOTICE`, and embedded MIT notices are present |

The FPScanner directory also contains vendored source inputs for fp-collect and
ua-parser-js 0.7.40. The ClientJS artifact contains a `0.7.41` ua-parser marker.
Exact local SHA-256 values and the limits of the recorded provenance are in
`assets/vendor/vendor-lock.json` and `THIRD_PARTY_NOTICES.md`.

### Runtime components embedded in the rebuilt ClientJS artifact

`assets/vendor/clientjs/clientjs-0.2.1.base.min.js` is not an untouched upstream
file. It was rebuilt from the declared ClientJS commit with ua-parser-js replaced
by 0.7.41. The base entry and that commit's lock identify these reachable runtime
components:

| Component | Version | Relationship | License |
|---|---:|---|---|
| globalthis | 1.0.2 | direct import `globalthis/polyfill` | MIT |
| define-properties | 1.1.3 | runtime dependency of globalthis | MIT |
| object-keys | 1.1.1 | runtime dependency of define-properties | MIT |
| murmurhash-js | 1.0.0 | direct import `murmurhash3_gc` | MIT |
| ua-parser-js | 0.7.41 | direct import; locally substituted rebuild input | MIT |
| fontdetect | 0.3 | vendored ClientJS source imported by the base entry | Apache-2.0 |

`inherits` 2.0.4 is declared by the upstream ClientJS package but is not imported
by `src/client.base.js`; it is therefore not represented as embedded in this base
bundle. The component/version basis and upstream references are recorded once in
`assets/vendor/vendor-lock.json`. The retained artifact is minified and the exact
patched build tree is absent, so this inventory does not establish a reproducible
byte-for-byte rebuild.

## Repository development dependencies

`package.json` and the root `package-lock.json` pin:

- TypeScript `5.9.3` — Apache-2.0, development-only;
- `@types/node` `22.20.1` — MIT, development-only;
- transitive `undici-types` `6.21.0` — MIT, development-only.

The lockfile records registry integrity hashes and can be installed with
`npm ci --ignore-scripts`. Runtime core code uses Node.js built-ins; browser
control engines are stored as local artifacts.

## Known inventory gaps

- production Next.js/React routes, database code, UI, and exporters are not in
  this repository and are not represented here;
- the repository does not contain all inputs needed to reproduce the FPScanner or
  ClientJS bundles byte-for-byte;
- ThumbmarkJS and FingerprintJS artifacts, plus FPScanner/fpcollect/ua-parser
  source inputs, are pinned to and verified against published npm tarballs, but
  source-level rebuilds have not been reproduced;
- ClientJS now has an adjacent modification `NOTICE` and local copies of all
  identified embedded license notices, but the minified JavaScript itself has no
  modification header; final Apache-2.0 section 4(b) packaging treatment still
  needs confirmation;
- no generated vulnerability scan or formal transitive-license report is
  committed; run a separate package-manager audit as a release gate.

This inventory must be extended from the final release tree after the missing
server application and its own dependency lock are included.
