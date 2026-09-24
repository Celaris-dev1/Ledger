#!/usr/bin/env bash
# Runs every native Go fuzz target in the module for FUZZTIME (default 10s) each.
# Usage: .github/fuzz.sh [fuzztime]   e.g. .github/fuzz.sh 120s for a longer local run.
# A crasher is written to <pkg>/testdata/fuzz/<Target>/ by go test; commit it as a seed.
set -euo pipefail
FUZZTIME="${1:-${FUZZTIME:-10s}}"
failed=0
for pkg in $(go list ./...); do
  targets=$(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)
  for t in $targets; do
    echo "::group::$pkg $t ($FUZZTIME)"
    if ! go test "$pkg" -run '^$' -fuzz "^${t}\$" -fuzztime "$FUZZTIME"; then
      echo "::error::fuzz target $pkg.$t failed"
      failed=1
    fi
    echo "::endgroup::"
  done
done
exit $failed
