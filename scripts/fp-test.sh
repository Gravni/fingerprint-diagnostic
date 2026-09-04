#!/usr/bin/env bash
# Fingerprint module regression harness (Codex v4 §Regression/CI, P11).
# Discovers every fp-*.test.{mjs,mts} under scripts/ so a newly-added test
# cannot be forgotten in CI.  TypeScript declaration fixtures are covered by
# the preceding `npm run typecheck` step in `npm run verify`.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
run() { echo "── $1"; if node "$1"; then :; else fail=1; fi; echo; }

runts() { echo "── $1"; if node --experimental-strip-types "$1"; then :; else fail=1; fi; echo; }

for test_file in scripts/fp-*.test.mjs; do
  run "$test_file"
done
for test_file in scripts/fp-*.test.mts; do
  runts "$test_file"
done

if [ "$fail" -ne 0 ]; then echo "❌ fingerprint tests FAILED"; exit 1; fi
echo "✅ all fingerprint tests passed"
