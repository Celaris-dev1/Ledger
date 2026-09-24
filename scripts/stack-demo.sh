#!/usr/bin/env bash
# stack-demo.sh: runs one real, small goal across Warrant, Harbour, Gate and Proof (built as
# real binaries from their worktrees/checkouts next to this one, via `go build` — never `go
# run`), talking to a real Ledger server, then renders the cross-product incident report for
# that goal and asserts the chain of custody is complete and every source chain verifies.
#
# This drives the existing cross-product harness in e2e/xproduct_test.go (which already builds
# and runs Warrant, Harbour-, Gate and Proof as subprocess daemons against a real ledgerd and a
# real goal) rather than re-implementing that orchestration in bash: that harness is the one
# thing in this repo that actually knows each product's CLI flags, env vars and HTTP contracts,
# and duplicating it here would drift out of sync with it. This script's job is: build, drive
# it, dump the resulting incident report, and assert on it as a *demo* artifact (HTML you can
# open), independent of `go test` passing/failing as a unit test.
#
# Usage: scripts/stack-demo.sh [--root DIR]
#   --root DIR   directory holding the sibling Gate, Warrant, Harbour-, Proof checkouts
#                (default: LEDGER_XPRODUCT_ROOT, else this script's own worktrees layout
#                /home/user/wt, else the directory next to this repo)
#
# Requires: go 1.24+, psql, git, python3, node, npm (same as scripts/e2e.sh) and a reachable
# Postgres at LEDGER_TEST_DATABASE_URL (default postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable).
#
# Output: writes stack-demo-out/incident.{json,html,md} and stack-demo-out/records.json, and
# exits non-zero if the goal did not produce a complete, verified chain across all four products.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

ROOT="${LEDGER_XPRODUCT_ROOT:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    *) echo "stack-demo: unknown arg $1" >&2; exit 2 ;;
  esac
done
if [ -z "$ROOT" ]; then
  for candidate in /home/user/wt "$(dirname "$REPO_ROOT")"; do
    if [ -d "$candidate/Warrant" ] && [ -d "$candidate/Gate" ]; then
      ROOT="$candidate"
      break
    fi
  done
fi
if [ -z "$ROOT" ] || [ ! -d "$ROOT/Warrant" ]; then
  echo "stack-demo: cannot find sibling Gate/Warrant/Harbour-/Proof checkouts; pass --root DIR" >&2
  exit 2
fi
echo "stack-demo: using sibling checkouts under $ROOT"

for tool in go psql git python3 node npm; do
  command -v "$tool" >/dev/null || { echo "stack-demo: $tool is required" >&2; exit 2; }
done

export LEDGER_TEST_DATABASE_URL="${LEDGER_TEST_DATABASE_URL:-postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable}"

OUT_DIR="$REPO_ROOT/stack-demo-out"
DUMP_DIR="$(mktemp -d)"
LOG_FILE="$(mktemp)"
DAEMON_PIDS=()

cleanup() {
  # Kill only PIDs this script itself started (never pkill/pgrep -f).
  for pid in "${DAEMON_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$DUMP_DIR" "$LOG_FILE"
}
trap cleanup EXIT INT TERM

mkdir -p "$OUT_DIR"

echo "stack-demo: building ledger/ledgerd (go build, no go run)"
go build -o "$DUMP_DIR/ledger" ./cmd/ledger
go build -o "$DUMP_DIR/ledgerd" ./cmd/ledgerd
echo "stack-demo: ledger $("$DUMP_DIR/ledger" --help 2>&1 | head -1 || true)"

# The cross-product scenario itself: builds real Warrant/Harbour-/Gate/Proof binaries from
# $ROOT (go build, no go run — see e2e/xproduct_test.go's goBuild), runs them as real
# subprocess daemons against a real ledgerd, issues a Warrant token, has Harbour run an effect
# with it, has Gate verify a run, has Proof capture a fetch — all under one shared goal_id —
# then asserts every record lands in `ledger incident --goal`. go test owns that harness's own
# process lifecycle (each daemon is registered with t.Cleanup, killed by PID when the test
# binary exits); nothing here needs a second trap for those PIDs.
echo "stack-demo: running the cross-product scenario (builds + runs Warrant/Harbour/Gate/Proof)"
LEDGER_XPRODUCT=1 \
LEDGER_XPRODUCT_ROOT="$ROOT" \
LEDGER_XPRODUCT_DUMP="$DUMP_DIR" \
  go test -tags e2e -count=1 -timeout 15m -run TestCrossProductIncident -v ./e2e 2>&1 | tee "$LOG_FILE"

if [ ! -s "$DUMP_DIR/incident.json" ]; then
  echo "stack-demo: FAIL — no incident.json was dumped (scenario did not complete)" >&2
  exit 1
fi

GOAL_ID="$(python3 -c "import json,sys; print(json.load(open('$DUMP_DIR/incident.json'))['goal_id'])")"
# The scenario's ledgerd runs against a scratch database that go test drops on exit, so these
# are the same `ledger incident --goal ... --format ...` outputs the test itself produced
# against the live database, dumped to disk (see e2e/xproduct_test.go LEDGER_XPRODUCT_DUMP)
# rather than a stale re-run against a database that no longer exists.
cp "$DUMP_DIR/incident.json" "$OUT_DIR/incident.json"
cp "$DUMP_DIR/records.json" "$OUT_DIR/records.json" 2>/dev/null || true
cp "$DUMP_DIR/incident.html" "$OUT_DIR/incident.html" 2>/dev/null || echo "stack-demo: note — incident.html not dumped (older e2e build?)"
cp "$DUMP_DIR/incident.md" "$OUT_DIR/incident.md" 2>/dev/null || true

echo "stack-demo: goal $GOAL_ID — asserting the chain of custody is complete and verified"
python3 - "$OUT_DIR/incident.json" "$GOAL_ID" <<'PY'
import json, sys
path, goal = sys.argv[1], sys.argv[2]
rep = json.load(open(path))
s = rep["summary"]
errs = []
if rep.get("goal_id") != goal:
    errs.append(f"goal_id mismatch: {rep.get('goal_id')!r} != {goal!r}")
if not s.get("all_chains_intact"):
    errs.append("not all source chains verify (hash-chain integrity failed)")
chains_present = {c["chain"] for c in rep.get("chains", [])}
for want in ("warrant", "harbour", "gate", "proof"):
    if want not in chains_present:
        errs.append(f"missing product in incident: {want}")
if s.get("records", 0) < 4:
    errs.append(f"too few records for a real cross-product goal: {s.get('records')}")
if s.get("denials", 0) < 1:
    errs.append("expected at least one denial in the scenario (authz boundary not exercised)")
if s.get("effects_committed", 0) < 1:
    errs.append("expected at least one committed effect (Harbour ran something)")
receipts = rep.get("receipts") or []
if receipts:
    failed = [r for r in receipts if not r.get("signature_ok")]
    if failed:
        errs.append(f"{len(failed)}/{len(receipts)} stack-receipts failed verification: {failed}")
    print(f"stack-demo: {len(receipts)} stack-receipt(s) found, all verified")
else:
    print("stack-demo: NOTE — no stack-receipt/v1 envelopes found on this goal's records yet "
          "(products emit them at their existing ledger.Append call sites; see docs/receipt-spec.md)")
if errs:
    print("stack-demo: FAIL")
    for e in errs:
        print("  -", e)
    sys.exit(1)
print(f"stack-demo: OK — {s['records']} records across {s['chains']} chains "
      f"({', '.join(sorted(chains_present))}), all chains verify, "
      f"{s['effects_committed']} effect(s) committed, {s['denials']} denial(s).")
PY

echo "stack-demo: wrote $OUT_DIR/incident.{json,html,md}"
