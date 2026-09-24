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
| POST | `/v1/records` | body `{chain,type,goal_id?,actor_chain[],policy_version?,payload,idempotency_key?}` → 201 `{id,chain,seq,hash,prev_hash,created_at,idempotency_key?}`. `actor_chain` must be non-empty and start with `kind:"human"` (400 otherwise). `idempotency_key`, when set, is unique per `chain`: a retry with the same `(chain, idempotency_key)` returns the original record's response instead of appending a duplicate. |
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
Both are durable and async: `record()` returns immediately after appending to an on-disk JSONL
spool, and a background sender delivers it with retries (exponential backoff + jitter),
surviving process restarts and ledgerd outages without reordering or dropping records. Every
record carries an auto-generated `idempotency_key`, so a retried POST `/v1/records` (same
`chain` + `idempotency_key`) returns the original record instead of appending a duplicate —
this is additive and contract-compatible; callers who never set it are unaffected. Call
`flush()`/`await flush()` to wait for the spool to drain (e.g. in a short script); this also
runs automatically on process exit. `actor_chain` helpers (`ledger_sdk.actor_chain` /
`@celaris/ledger-sdk/actorChain`: `human`/`agent`/`service`/`build`/`extend`) keep the
originating human first while appending delegation hops, and a `ledger.*` vocabulary
(`ledger_sdk.vocab` / `@celaris/ledger-sdk/vocab`: `goal.created`, `step.planned`,
`action.attempted`, `action.completed`, `verification.recorded`, `approval.requested`/
`granted`/`denied`, `budget.charged`) gives framework adapters a stable set of event names.

### Framework adapters (optional extras — a few lines to instrument any agent loop)

Python (`pip install ledger-sdk[langchain|crewai|autogen|openhands]`, imported only when used):

```python
from ledger_sdk.adapters.langchain import LedgerCallbackHandler
chain.invoke(x, config={"callbacks": [LedgerCallbackHandler(ledger, human_id="alice")]})
```

- `ledger_sdk.adapters.langchain.LedgerCallbackHandler` — LangChain/LangGraph chain/tool/LLM start/end/error.
- `ledger_sdk.adapters.crewai.LedgerCrewCallback` — CrewAI `step_callback`/`task_callback`.
- `ledger_sdk.adapters.autogen.LedgerMessageHook` — AutoGen `register_hook`/intervention-handler message hooks.
- `ledger_sdk.adapters.openhands.LedgerEventSubscriber` — OpenHands `EventStream.subscribe` callback.

TypeScript:

```ts
import { LedgerCallbackHandler } from "@celaris/ledger-sdk/adapters/langchain";
await chain.invoke(x, { callbacks: [new LedgerCallbackHandler(ledger, "alice")] });
```

- `@celaris/ledger-sdk/adapters/langchain` — LangChain.js callback handler (peer dep `@langchain/core`, optional).
- `@celaris/ledger-sdk/withLedger` — generic `withLedger(ledger, humanId, name, fn)` wrapper for any tool function:
  `const search = withLedger(ledger, "alice", "search", rawSearch);`

Each adapter maps its framework's events onto the `ledger.*` vocabulary, carries goal/run ids
and model/version, and keeps the human actor first. Adapter tests use lightweight fakes of
each framework's callback interfaces (no heavy install required); the LangChain/LangChain.js
adapters additionally run a real integration test against `langchain-core`/`@langchain/core`
in CI.

## Tests

```sh
go vet ./... && go test ./...                                      # DB tests skip
LEDGER_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/ledger?sslmode=disable go test ./...
(cd sdk/python && python3 -m unittest)
(cd sdk/ts && npm ci && npm test)
```

DB tests run in a throwaway schema per test and drop it afterwards.

## Built vs roadmap

Built: schema + migrations, append-only triggers, per-chain hash chain with serialized appends,
HTTP API (incl. optional `idempotency_key` on `POST /v1/records`), CLI (verify/replay/export/
anchor), Ed25519 signed roots to files, JSON+HTML auditor pack (EU AI Act Art. 12/14), durable
async Python and TS SDKs (spool + retries + idempotency + actor_chain/vocab helpers) with
framework adapters for LangGraph/LangChain, CrewAI, AutoGen, OpenHands (Python) and
LangChain.js + a generic `withLedger` wrapper (TS), tamper tests.

Not yet built (the "fully built version"):
- Anchoring to an external public timestamping service (RFC 3161 / transparency log) or automatic
  scheduled commits of the anchor dir to a public repo; today `ledger anchor` is run by cron/CI.
- Live replay UI (timeline scrubbing); only JSON replay and a static HTML narrative exist.
- PDF rendering of the narrative (HTML only today; print-to-PDF works).
- Automatic projection of record types into `goal_steps`, `action_attempts`,
  `verification_results`, `approval_requests`, `budget_ledger` (tables exist; only `operators`
  and `goals` are populated automatically).
- Cross-product incident review joining Gate/Proof/Warrant chains into one narrative
  (export by `goal_id` already spans chains).
- Retention tiers and per-regime templates (SOC 2, HIPAA); key rotation / KMS-held keys.
