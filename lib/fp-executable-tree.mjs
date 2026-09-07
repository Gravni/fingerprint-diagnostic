// Closed source tree used for the runtime build identity. The capture process
// refuses to start when a file below lib/ or scripts/ is missing, added without
// review, or replaced by a symlink. Keep this list explicit in code review.
export const FP_EXECUTABLE_TREE = Object.freeze({
  roots: Object.freeze(["lib", "scripts"]),
  files: Object.freeze([
    "lib/fp-blob.d.mts",
    "lib/fp-blob.mjs",
    "lib/fp-compare.mjs",
    "lib/fp-encode.mjs",
    "lib/fp-executable-tree.d.mts",
    "lib/fp-executable-tree.mjs",
    "lib/fp-expect.d.mts",
    "lib/fp-expect.mjs",
    "lib/fp-provenance.d.mts",
    "lib/fp-provenance.mjs",
    "lib/fp-probe-artifact.d.mts",
    "lib/fp-probe-artifact.mjs",
    "lib/fp-readiness.mjs",
    "lib/fp-readiness.d.mts",
    "lib/fp-schema.d.mts",
    "lib/fp-schema.mjs",
    "lib/fp-vectors.ts",
    "lib/h2-observe.mjs",
    "lib/h2-observe.d.mts",
    "lib/ja4.ts",
    "lib/md5.d.mts",
    "lib/md5.mjs",
    "scripts/capture-server.mjs",
    "scripts/fp-audio.test.mjs",
    "scripts/fp-blob.test.mjs",
    "scripts/fp-capture.test.mjs",
    "scripts/fp-compare.test.mjs",
    "scripts/fp-controls.test.mjs",
    "scripts/fp-encode.test.mjs",
    "scripts/fp-h2.test.mjs",
    "scripts/fp-ja4.test.mts",
    "scripts/fp-md5.test.mjs",
    "scripts/fp-probe.test.mjs",
    "scripts/fp-probe-artifact.test.mjs",
    "scripts/fp-provenance.test.mjs",
    "scripts/fp-readiness.test.mjs",
    "scripts/fp-schema.test.mjs",
    "scripts/fp-sw.test.mjs",
    "scripts/fp-test.sh",
    "scripts/fp-types.compile.mts",
    "scripts/fp-vendor.test.mjs",
  ]),
});

// Browser-collector build inputs (reviewer 2026-09-07 #9). The rendered probe
// artifact is a function of the template, the encoder it inlines AND the
// renderer that assembles them — a renderer change yields different executable
// HTML, so it MUST move browserCollectorBuild. This list is the closed manifest
// for that identity: the panel's deploy descriptor hashes exactly these files
// (sorted, path\0bytes) and refuses to start if any is missing; the provenance
// test asserts the renderer's static import closure is covered by this list and
// that every lib/ entry is part of FP_EXECUTABLE_TREE (so an unlisted or
// drifted file breaks the whole-tree capture build as well).
export const FP_COLLECTOR_INPUTS = Object.freeze([
  "assets/fingerprint-probe.html",
  "lib/fp-encode.mjs",
  "lib/fp-probe-artifact.mjs",
]);
