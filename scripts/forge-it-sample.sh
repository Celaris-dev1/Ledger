#!/usr/bin/env bash
# Regenerates the deterministic sample bundle published in docs/forge-it/ for the "Forge It"
# public challenge (see docs/forge-it.md). No database, no network, no private key committed:
# the signing key is generated in memory by tools/forge-it-sample and discarded.
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./tools/forge-it-sample docs/forge-it
