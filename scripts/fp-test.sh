#!/usr/bin/env bash
# Fingerprint module regression harness (Codex v4 §Regression/CI, P11).
# Runs every fp-*.test.* under scripts/. Add new tests here as phases land.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
run() { echo "── $1"; if node "$1"; then :; else fail=1; fi; echo; }

run scripts/fp-encode.test.mjs   # typed value encoder (shared module: types, buffers+content-hash, cloneability, JSON round-trip)
run scripts/fp-schema.test.mjs   # measurement schema + schemaStatus + legacy fixture
run scripts/fp-compare.test.mjs  # comparator rules (unavailable≠leaked, no verdicts w/o profile)
run scripts/fp-vendor.test.mjs   # vendored control engines: SHA pins + telemetry off
runts() { echo "── $1"; if node --experimental-strip-types "$1"; then :; else fail=1; fi; echo; }
runts scripts/fp-ja4.test.mts    # JA4/JA3 official vectors + ClientHello parser fuzz/bounds

if [ "$fail" -ne 0 ]; then echo "❌ fingerprint tests FAILED"; exit 1; fi
echo "✅ all fingerprint tests passed"
