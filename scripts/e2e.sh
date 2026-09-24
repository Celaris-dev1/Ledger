#!/usr/bin/env bash
# End-to-end suite: builds the real ledgerd + ledger binaries and runs them against Postgres,
# the Python/TS SDKs as subprocesses, fake TSAs + a bare git repo, psql as superuser, and a
# headless Chromium via Playwright. See e2e/*.go.
#
#   scripts/e2e.sh                      # everything except the cross-product scenario
#   LEDGER_XPRODUCT=1 scripts/e2e.sh    # also build Gate/Warrant/Harbour-/Proof (sibling checkouts)
#   scripts/e2e.sh -run Tenancy         # extra args go to `go test`
#
# Env: LEDGER_TEST_DATABASE_URL (default: local postgres), LEDGER_E2E_CHROMIUM (Chromium binary;
# default /opt/pw-browsers/chromium-1194/chrome-linux/chrome, the UI test skips if missing),
# LEDGER_E2E_PLAYWRIGHT_DIR (dir with node_modules/playwright; default: npm install into a temp
# dir), LEDGER_XPRODUCT_ROOT (dir holding the sibling repos), LEDGER_XPRODUCT_STRICT=1 (fail on
# known product-side contract gaps too).
set -euo pipefail
cd "$(dirname "$0")/.."
export LEDGER_TEST_DATABASE_URL="${LEDGER_TEST_DATABASE_URL:-postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable}"
for tool in psql git python3 node npm; do
  command -v "$tool" >/dev/null || { echo "e2e: $tool is required" >&2; exit 2; }
done
exec go test -tags e2e -count=1 -timeout 20m -v ./e2e "$@"
