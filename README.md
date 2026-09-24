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
| GET | `/v1/chains/{chain}/root` | → `{chain,seq,head,signature,public_key,key_id,signed_at}` |
| GET | `/v1/chains/{chain}/anchors[?verify=1]` | → `{chain,anchors:[receipt...]}`; with `verify=1` also `verification` (offline re-check, see "External anchoring"). 501 if not configured. |
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

## External anchoring

Goal: a compromised DB administrator cannot silently rewrite history. The admin *can* disable the
append-only trigger, edit a record, recompute every later hash and fix `chains.head_hash`; plain
`ledger verify` then passes because the chain is internally consistent. What they cannot do is
forge third-party time-stamps over the old root, rewrite commits already pushed to a repository
they don't control, or sign new roots without the Ed25519 key. `ledger verify --anchors` checks
exactly that (`internal/anchoring/pg_test.go:TestEndToEndRewriteDetection` performs the attack).

**What is anchored.** A signed root `{chain,seq,head,signature,public_key,key_id}`. The
anchoring digest (RFC 3161 `messageImprint`) is `sha256("ledger-chain-root/v1\n<chain>\n<seq>\n<head>")`,
i.e. the digest of the exact message the Ed25519 signature covers.

**Backends** (`internal/anchoring`, behind one `Backend` interface):

| Backend | Env | Receipt stored |
|---|---|---|
| RFC 3161 TSAs, N-of-M | `LEDGER_TSA_URLS="freetsa=https://freetsa.org/tsr,digicert=http://timestamp.digicert.com,sectigo=https://timestamp.sectigo.com"`, `LEDGER_TSA_TRUST=/path/roots.pem` (required), `LEDGER_TSA_QUORUM=2` (default: all) | the TimeStampToken DER per TSA, genTime, signer, serial, nonce |
| git repository | `LEDGER_ANCHOR_GIT_REMOTE=<url or path>`, `LEDGER_ANCHOR_GIT_DIR=<local clone>`, `LEDGER_ANCHOR_GIT_BRANCH=main`, `LEDGER_ANCHOR_GIT_SIGN=1` (adds `-S`) | commits `roots/<chain>/<seq>.json` with the git CLI, pushes, records the commit sha |
| local directory | `LEDGER_ANCHOR_DIR` | same file layout as `ledger anchor` |

The RFC 3161 client (`internal/anchor/tsa`) is stdlib-only: it builds the `TimeStampReq` with
`encoding/asn1` (SHA-256, random nonce, `certReq`), POSTs `application/timestamp-query`, and verifies
the response: PKIStatus, `id-ct-TSTInfo`, messageImprint = our digest, nonce, signedAttrs
(`contentType`, `messageDigest`, ESS `signingCertificate[V2]`), the CMS signature (RSA PKCS#1 v1.5/PSS,
ECDSA, Ed25519) and the signer chain to the trust bundle with the `timeStamping` EKU, evaluated at
genTime. `github.com/digitorus/timestamp` was not used: it parses tokens but leaves signature/chain
verification to the caller, and verifying ourselves avoids a new dependency. The trust bundle must
contain the TSAs' roots (e.g. freetsa's `cacert.pem`, DigiCert/Sectigo roots).

**Scheduling.** `ledgerd` anchors every chain's head when `LEDGER_ANCHOR_EVERY=N` new records have
accumulated and/or every `LEDGER_ANCHOR_INTERVAL` (e.g. `1h`) if the head moved; heads are polled
every `LEDGER_ANCHOR_POLL` (default `10s`). Chains that fail verification are never anchored. On
demand: `ledger anchor --external [--chain X]`. Receipts are verified before being stored in the
append-only `anchor_receipts` table (migration `0100`), which also makes the legacy `anchors` table
append-only. A backend failing (no network, TSA down) is logged and the others still anchor; below
the TSA quorum the tokens that did arrive are still kept.

**Verification.** `ledger verify --anchors [--chain X] [--json]` (exit 1 on any finding), or
`GET /v1/chains/{chain}/anchors?verify=1`. Offline, from stored bytes only: each receipt's signed root
is checked (signature, and key trusted — see below), each TSA token is re-verified against the trust
bundle, each git receipt is checked against the local clone (`git show <sha>:<path>`), and each
anchored `(seq, head)` must equal the current record hash at that seq — together with an intact hash
chain that proves the anchored state is a prefix of today's chain. Roots found in `LEDGER_ANCHOR_DIR`
and in the git clone's `roots/` are checked too, so deleting receipt rows does not hide a rewrite.
Example report:

```
REWRITTEN gate/runs  length=8 head=d267… anchors=14 (ok=0 rewritten=14 …) last_anchored_seq=0
  ! HISTORY REWRITTEN: … records in seq range (0, 5] were altered or removed after being anchored
  !   seq 5: anchored head a49b… witnessed by [file, git, rfc3161:tsa0, rfc3161:tsa1, rfc3161:tsa2, dir, dir]; current record hash is 6131…
```

**Key rotation.** With `LEDGER_KEYRING_DIR` set, signing keys live in a keyring (`<id>.pub` for every
key, `<id>.key` only for the active one, `active`); an existing `LEDGER_KEY_FILE`/`LEDGER_SIGNING_KEY`
is imported on first use. Key ids are `ed25519:<first 16 hex of sha256(pub)>` and appear as `key_id`
in roots (additive; the signed message is unchanged, so old roots verify). `ledger keys rotate`
creates a new key, deletes the old private key (`--keep-old` to keep it), and appends a
`ledger.key.rotated` record — signed by both old and new key — to the `ledger` system chain. The
trusted key set for `verify --anchors` is the keyring's public keys plus keys introduced by valid,
correctly chained rotation records. Without a keyring, roots are checked against their embedded key
only (reported as a warning). Restart `ledgerd` after a rotation.

**Live test.** `LEDGER_LIVE_TSA=1 go test ./internal/anchor/tsa -run Live -v` stamps against
freetsa.org and verifies the real token (trust root fetched from freetsa.org over TLS, or
`LEDGER_LIVE_TSA_TRUST=<pem>`).

**Not built: Sigstore Rekor.** A `hashedrekord` entry needs the artifact signed with an x509/PKIX key
Rekor accepts, and meaningful offline verification needs Rekor's public key plus checking the signed
entry timestamp and Merkle inclusion proof. That is feasible with the stdlib but was left out to
keep this change reviewable; the `Backend` interface is where it would plug in.

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

## Web UI and access control

ledgerd serves an auditor-facing UI on the same port as the API (html/template + a little
vanilla JS, embedded with `embed.FS`, no build step). Disable it with `LEDGER_UI=off` (API only).

| Page | What it shows |
|---|---|
| `/chains`, `/chains/{chain}` | length, head, verification status, last external anchor and its witnesses; paged records |
| `/goals?q=&status=` | goal search over the projections |
| `/goals/{id}` | **live replay** timeline + goal → steps → attempts → verifications/approvals tree |
| `/approvals?status=` | approval queue (pending / approved / denied) |
| `/budgets?goal=` | budget groups, running balances, overspend |
| `/incidents/{goal}` | the cross-product incident narrative (downloads for auditors) |
| `/r/{chain}/{seq}` | record permalink; the hash is **re-computed in your browser** |
| `/admin` | API tokens and SSO users (admin) |

**Replay.** Records are laid out on per-chain lanes by time (T+0 = first record). Scrub with the
slider, play/pause (Space) at 0.25–60×, step with ← →, jump from the event list or from any
evidence link in the goal tree (`?at=chain:seq` deep-links). Idle gaps are skipped while playing.
The side panel shows payload, actor chain (originating human first; a violation is flagged),
policy version, hash, prev hash, an in-browser hash check, chain verification and anchor status for
that seq. **Live** subscribes to `GET /v1/stream` and extends the timeline as records arrive.

**Stream.** `GET /v1/stream?chain=&goal_id=` is Server-Sent Events: `event: record`, `data` = the
record JSON, `id` = the per-chain cursor after it (`gate=12&ledger=40`). Reconnects resume with
`Last-Event-ID` (or `?cursor=`) without gaps or duplicates; without a cursor it starts at the
current heads (`?from=start` replays). It is backed by bounded, indexed per-chain reads woken by
Postgres `LISTEN/NOTIFY` (trigger from migration `0300`), with a poll fallback (`LEDGER_STREAM_POLL`, default 2s).

**Browser verification.** `static/canon.js` is an independent implementation of the canonical
JSON (literal-preserving parser, keys sorted by UTF-8 bytes, Go's exact string escaping) and the
record hash, using WebCrypto SHA-256 (a pure-JS fallback on non-secure origins). A golden test runs
it under node against Go's `internal/canon` on hostile inputs.

**Security.** Strict CSP (`script-src 'self'; style-src 'self'`, no inline code), untrusted values
only via html/template or `textContent`, `nosniff`, `frame-ancestors 'none'`, same-origin referrer,
HSTS over TLS, `Cache-Control: no-store` on pages.

### Roles

| | append | contract reads (records, verify, replay, root) | UI, projections, stream, anchors | export (packs, incident downloads) | tokens & users |
|---|---|---|---|---|---|
| admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| auditor | | ✓ | ✓ | ✓ | |
| viewer | | ✓ | ✓ | | |
| writer | ✓ | ✓ | | | |

- **API tokens** (`ldg_…`) are stored as SHA-256 only: `ledger token create --name harbour --role writer`,
  `ledger token list`, `ledger token revoke ID`, or the `/admin` page. Admin/auditor/viewer tokens can
  also sign in to the UI; writer tokens cannot.
- **`LEDGER_TOKEN`** keeps working unchanged for the products, now as a writer
  (`LEDGER_TOKEN_ROLE` to change that; not recommended).
- **SSO**: OIDC authorization code + PKCE (`LEDGER_OIDC_ISSUER`, `LEDGER_OIDC_CLIENT_ID`,
  `LEDGER_OIDC_CLIENT_SECRET`, `LEDGER_OIDC_REDIRECT_URL`=`https://host/auth/callback`,
  `LEDGER_OIDC_SCOPES`, `LEDGER_OIDC_DEFAULT_ROLE` (viewer), `LEDGER_OIDC_ADMIN_EMAILS`,
  `LEDGER_OIDC_AUDITOR_EMAILS`, `LEDGER_OIDC_ALLOW_DOMAINS`). Role grants and domain checks only
  honour emails with `email_verified=true`; `email_verified=false` is refused. Roles are re-read
  on every request (demotion/disable is immediate).
- **Sessions**: random id in an HttpOnly SameSite=Lax cookie (Secure over TLS or with
  `LEDGER_SECURE_COOKIES=1`), SHA-256 at rest, `LEDGER_SESSION_TTL` (12h). Unsafe cookie
  requests need the CSRF token (form field or `X-CSRF-Token`) and a same-origin `Origin`/`Referer`;
  login redirects accept local paths only.
- **Open mode**: with no `LEDGER_TOKEN`, no SSO and no API tokens at startup, ledgerd behaves as
  before (no authentication) and the UI shows a warning banner. `LEDGER_AUTH=on|off` forces it.
  Creating the first token takes effect at the next restart.

Screenshots (light/dark): [`docs/screenshots/`](docs/screenshots/).

## Built vs roadmap

Built: schema + migrations, append-only triggers, per-chain hash chain with serialized appends,
HTTP API (incl. optional `idempotency_key` on `POST /v1/records`), CLI (verify/replay/export/
anchor), Ed25519 signed roots to files, external anchoring (RFC 3161 N-of-M TSAs, git repo, dir)
with scheduled anchoring and offline `verify --anchors` rewrite detection, key ids + keyring
rotation, JSON+HTML auditor pack (EU AI Act Art. 12/14), durable async Python and TS SDKs (spool +
retries + idempotency + actor_chain/vocab helpers) with framework adapters for LangGraph/LangChain,
CrewAI, AutoGen, OpenHands (Python) and LangChain.js + a generic `withLedger` wrapper (TS), tamper
tests, incremental/rebuildable projections into all domain tables with a query API, cross-product
incident review (JSON/HTML/Markdown), auditor web UI with live replay timeline over SSE,
in-browser record re-verification, RBAC (admin/auditor/viewer/writer), hashed API tokens, OIDC SSO
with PKCE, sessions and CSRF protection.

Not yet built (the "fully built version"):
- Transparency-log anchoring (Sigstore Rekor). RFC 3161 N-of-M, scheduled git commits and
  `verify --anchors` are built (see "External anchoring").
- KMS/HSM-held signing keys (file keyring with rotation is built).
- Anchor receipts are not yet included in the auditor pack.
- CrewAI, AutoGen and OpenHands adapters are tested against stubs only (LangChain is tested for real).
- UI: no pagination on goals/approvals lists; anchor status in the UI checks head consistency only
  (receipt signatures are re-verified by `ledger verify --anchors`); no per-goal/per-chain access
  scoping (roles are global); no SCIM/group-claim role mapping; open mode is decided at startup.
- PDF rendering of the narrative (HTML only today; print-to-PDF works).
- Projections: the query API loads the goal-filtered projection into memory per request (fine for
  thousands of rows per goal; no pagination on `/v1/goals` / `/v1/approvals` yet). Warrant calls
  without `goal_id` project goal-less approvals (linked to the goal only via token budgets and the
  incident review).
- Incident review scans every chain in memory to resolve cross-references (no ref index yet).
- Retention tiers and per-regime templates (SOC 2, HIPAA); KMS-held keys.
