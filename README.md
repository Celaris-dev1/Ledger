# Ledger

Tamper-evident, identity-bound decision log for agent systems. Every decision an agent
system makes — what was proposed, by which model/version, on whose authority, against which
policy, what executed, what the verifier saw — is appended to a per-chain SHA-256 hash chain
in Postgres, with signed chain roots you can anchor outside the database and an auditor pack
mapped to EU AI Act Articles 12 and 14.

Ledger connects the other products: Gate, Proof, Warrant, Harbour and Bench each write to
their own chain (chain name = product name) through the HTTP API below.

## Quickstart

```sh
docker compose up -d --build            # postgres + ledgerd on :8410
curl -s -XPOST localhost:8410/v1/records -d '{
  "chain":"gate","type":"gate.run.started","goal_id":"g-1",
  "actor_chain":[{"kind":"human","id":"alice"},{"kind":"agent","id":"coder","model":"m","model_version":"1"}],
  "policy_version":"pol-7","payload":{"repo":"acme/api"}}'
curl -s localhost:8410/v1/chains/gate/verify
curl -s localhost:8410/v1/goals/g-1/replay
```

Local (no Docker): `go run ./cmd/ledgerd` with `LEDGER_DATABASE_URL` pointing at Postgres 16.

CLI (talks to Postgres directly):

```sh
go build -o ledger ./cmd/ledger
ledger verify                       # all chains; exit 1 if any is broken
ledger replay --goal g-1            # ordered records for a goal (JSON)
ledger export --goal g-1 --out pack # pack/pack.json + pack/narrative.html
ledger anchor --dir anchors         # anchors/<chain>/<seq>.json + latest.json, Ed25519-signed
```

### Configuration

| env | default | meaning |
|---|---|---|
| `LEDGER_DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable` | Postgres |
| `LEDGER_ADDR` | `:8410` | listen address |
| `LEDGER_TOKEN` | unset | if set, every `/v1` call needs `Authorization: Bearer <token>` |
| `LEDGER_SIGNING_KEY` | unset | base64 Ed25519 seed (32 bytes) or private key (64 bytes) |
| `LEDGER_KEY_FILE` | `ledger_ed25519.key` | used when `LEDGER_SIGNING_KEY` is unset; generated (0600) if missing |
| `LEDGER_ANCHOR_DIR` | `anchors` | CLI anchor output directory |

## HTTP API

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/records` | body `{chain,type,goal_id?,actor_chain[],policy_version?,payload}` → 201 `{id,chain,seq,hash,prev_hash,created_at}`. `actor_chain` must be non-empty and start with `kind:"human"` (400 otherwise). |
| GET | `/v1/records?chain=&goal_id=&after_seq=&limit=` | → `{"records":[...]}` (limit default 100, max 1000) |
| GET | `/v1/chains/{chain}/verify` | → `{chain,ok,length,head,broken_at}` (+ `reason` when broken) |
| GET | `/v1/goals/{goal_id}/replay` | → `{"goal_id":..,"records":[...]}` ordered by time across chains |
| GET | `/v1/chains/{chain}/root` | → `{chain,seq,head,signature,public_key,signed_at}` |
| GET | `/v1/export?goal_id=` or `?chain=a&chain=b` `&format=json\|html\|zip` | auditor pack |
| GET | `/healthz` | liveness |

A full record is `{id,chain,seq,type,goal_id,actor_chain,policy_version,payload,created_at,prev_hash,hash}`.

### Hashing

```
hash = sha256hex(prev_hash + "\n" + canonical_json(body))
body = {actor_chain, chain, created_at, goal_id, id, payload, policy_version, seq, type}
```

Canonical JSON: keys sorted, no whitespace, no HTML escaping, number literals preserved
verbatim. `created_at` is RFC3339Nano UTC (microsecond precision); absent `goal_id` /
`policy_version` hash as `""`. The first record of a chain has `prev_hash = ""`.
Root signatures are Ed25519 over `"ledger-chain-root/v1\n<chain>\n<seq>\n<head>"`.

## Architecture

```
SDK (py/ts) ──HTTP──> ledgerd ──> Postgres
                        │   records (append-only, hash-chained; json cols keep exact hashed text)
                        │   chains  (head_seq/head_hash per chain; detects tail truncation)
                        │   anchors, operators, goals, goal_steps, action_attempts,
                        │   verification_results, approval_requests(action_hash), budget_ledger,
                        │   audit_events (append-only), tools, identity_facts, memory_items
ledger CLI ─────────────┘   verify / replay / export / anchor
```

- **Append path**: one transaction per record: `pg_advisory_xact_lock(chain)` serializes
  appends per chain, reads the chain head, computes the hash, inserts, advances the head, and
  projects actors into `operators` and the goal into `goals`.
- **Append-only**: `BEFORE UPDATE OR DELETE` row triggers and a `BEFORE TRUNCATE` trigger raise
  on `records`; `audit_events` is likewise append-only.
- **Verification** recomputes every hash, checks `seq` continuity, `prev_hash` linkage and the
  head pointer. `internal/store/store_test.go:TestTamperDetected` edits a row (bypassing the
  trigger as a superuser could) and shows verify reports `broken_at` at the edited seq; a forged
  re-hash moves the break to the next record.
- **Anchoring**: signed roots are written to a directory intended to be committed to a public
  repo (or shipped to a timestamping service), so a DB admin cannot silently rewrite history.
- **Approvals** bind to an exact action via `approval_requests.action_hash`.
- **Auditor pack** (`internal/export`): `pack.json` (all records + verification + signed roots)
  and `narrative.html` with sections for Art. 12(1), 12(2)(a–c), 12(3), 14(1–3), 14(4)(d–e),
  14(5). Templates are a separate layer so other regimes can be added.

## SDKs

- Python (`sdk/python`, stdlib only): `Ledger(chain).record(type, payload, actor_chain, goal_id=, policy_version=)`
- TypeScript (`sdk/ts`, no runtime deps): `new Ledger({chain}).record(type, payload, actorChain, {goalId, policyVersion})`

Both read `LEDGER_URL` / `LEDGER_TOKEN` and become no-op recorders when `LEDGER_URL` is unset.

## Tests

```sh
go vet ./... && go test ./...                                      # DB tests skip
LEDGER_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable go test ./...
(cd sdk/python && python3 -m unittest)
(cd sdk/ts && npm ci && npm test)
```

DB tests run in a throwaway schema per test and drop it afterwards.

## Projections and incident review

`internal/projection` turns records into `goals`, `goal_steps`, `action_attempts`,
`verification_results`, `approval_requests` (+ `approval_decisions`), `budget_ledger`,
`identity_facts`, `memory_items`, `tools`, `operators`.

- **Vocabulary (version 1)** for agents writing directly to Ledger: `ledger.goal.created|status`,
  `ledger.step.planned|status`, `ledger.tool.registered`, `ledger.action.attempted|completed`,
  `ledger.verification.recorded`, `ledger.approval.requested|granted|denied`,
  `ledger.budget.allocated|charged`, `ledger.identity.asserted`, `ledger.memory.written`.
  Required/optional payload fields and the mapping of every product type (`gate.*`, `proof.*`,
  `warrant.*`, `harbour.*`, `bench.*`) are in `internal/projection/vocab.go` and served at
  `GET /v1/projections/vocabulary`.
- **Approvals bind to `action_hash` = sha256(canonical_json(action))**. When a record carries
  `action`, the hash is recomputed from it and a claimed `action_hash` is ignored. A decision whose
  hash differs from its request's is stored with `matched=false` and never satisfies the request.
- **Budgets** keep a running balance per (goal, resource). Warrant tokens get one group per token
  (`max_calls` allocated, each allowed call charges 1). A charge that takes an allocated budget
  below zero is flagged `overspent`.
- **Incremental, idempotent, rebuildable.** Each record maps to ops (`projection_ops`). Every
  affected group (a goal, attempt, approval, budget line…) is recomputed from all of its ops,
  sorted by (created_at, chain, seq). Per-chain cursors live in `projection_cursors`. Because of
  this, any interleaving of chains gives the same rows as a rebuild; a property test checks this.
  Changing the projector `Version` triggers an automatic rebuild. ledgerd runs the projector
  asynchronously after each append (one coalesced pending run) and every 30s; set
  `LEDGER_PROJECTIONS=off` to disable it.
- CLI: `ledger project [--rebuild] [--check]`. `--check` compares the stored rows with a fresh
  in-memory rebuild and exits 1 on any difference.
- API: `GET /v1/goals`, `GET /v1/goals/{id}` (steps → attempts → verifications/approvals, each
  with evidence record ids, chain/seq and hashes), `GET /v1/approvals?status=`,
  `GET /v1/budgets/{goal}`.

**Incident review:** `ledger incident --goal ID [--format json|html|md] [--out FILE]` or
`GET /v1/incidents/{goal_id}?format=`. It joins every chain by `goal_id` and by explicit
cross-references in payloads (`run_id`/`*_run_id`, `token_id`/`parent_id`, `capture_id`,
`manifest_hash`, `action_hash`, `task_id`, `request_id`, `attempt_id`, and a run id used as
another product's goal_id), repeating until nothing new is found. The output is one ordered
narrative covering who authorised what, what ran, what was verified, which effects committed and
which did not (two-phase intent/result), and hash-chain verification status per source chain.
The HTML is self-contained (auto-escaped, strict CSP, no scripts) and the Markdown is escaped.

## Built vs roadmap

Built: schema + migrations, append-only triggers, per-chain hash chain with serialized appends,
HTTP API, CLI (verify/replay/export/anchor), Ed25519 signed roots to files, JSON+HTML auditor
pack (EU AI Act Art. 12/14), Python and TS SDKs, tamper tests, incremental/rebuildable projections
into all domain tables with a query API, cross-product incident review (JSON/HTML/Markdown).

Not yet built (the "fully built version"):
- Native adapters for LangGraph, CrewAI, AutoGen, OpenHands.
- Anchoring to an external public timestamping service (RFC 3161 / transparency log) or automatic
  scheduled commits of the anchor dir to a public repo; today `ledger anchor` is run by cron/CI.
- Live replay UI (timeline scrubbing); only JSON replay and a static HTML narrative exist.
- PDF rendering of the narrative (HTML only today; print-to-PDF works).
- Projections: the query API loads the goal-filtered projection into memory per request (fine for
  thousands of rows per goal; no pagination on `/v1/goals` / `/v1/approvals` yet). Warrant calls
  without `goal_id` project goal-less approvals (linked to the goal only via token budgets and the
  incident review).
- Incident review scans every chain in memory to resolve cross-references (no ref index yet).
- Retention tiers and per-regime templates (SOC 2, HIPAA); key rotation / KMS-held keys.
