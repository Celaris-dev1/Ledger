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
| `LEDGER_TOKENS` | unset | multi-tenancy: `token=tenant,...` (`*` = operator); replaces `LEDGER_TOKEN` |
| `LEDGER_DATA_KEY_DIR` | unset | per-subject data keys: enables `data_subject` payload encryption and `ledger erase` |
| `LEDGER_SIGNER` | `file` | `file`, `vault` or `awskms` root/document signer (see "Key management") |
| `LEDGER_MAX_BODY_BYTES` | `4194304` | largest `POST /v1/records` body (413 beyond) |
| `LEDGER_MAX_PAGE` | `1000` | default and maximum page of `GET /v1/goals` and `GET /v1/approvals` (`?limit=&after=`, response `next_after`) |
| `LEDGER_MAX_EXPORT_RECORDS` | `200000` | largest `GET /v1/export` / replay response (413 beyond; page `GET /v1/records` or use `ledger backup`) |
| `LEDGER_REQUEST_TIMEOUT` | `2m` | per-request deadline for `/v1` API calls |

## HTTP API

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/records` | body `{chain,type,goal_id?,actor_chain[],policy_version?,payload,idempotency_key?}` → 201 `{id,chain,seq,hash,prev_hash,created_at,idempotency_key?}`. `actor_chain` must be non-empty (at most 64 hops) and start with `kind:"human"`; `payload` must be a JSON object; names (`chain`, `goal_id`, `idempotency_key`, actor ids) are at most 512 bytes, `type`/`policy_version` 256, and no field may contain NUL (400 otherwise). `idempotency_key`, when set, is unique per `chain`: a retry with the same `(chain, idempotency_key)` returns the original record's response instead of appending a duplicate. |
| GET | `/v1/records?chain=&goal_id=&after_seq=&limit=` | → `{"records":[...]}` (limit default 100, max 1000) |
| GET | `/v1/chains/{chain}/verify` | → `{chain,ok,length,head,broken_at}` (+ `reason` when broken) |
| GET | `/v1/goals/{goal_id}/replay` | → `{"goal_id":..,"records":[...]}` ordered by time across chains |
| GET | `/v1/chains/{chain}/root` | → `{chain,seq,head,signature,public_key,key_id,signed_at}` |
| GET | `/v1/chains/{chain}/anchors[?verify=1]` | → `{chain,anchors:[receipt...]}`; with `verify=1` also `verification` (offline re-check, see "External anchoring"). 501 if not configured. |
| GET | `/v1/export?goal_id=` or `?chain=a&chain=b` `&format=json\|html\|zip` | auditor pack |
| GET | `/healthz` | liveness |

Additive fields: `POST /v1/records` accepts an optional `data_subject`. It is never stored; see
"Retention, legal holds, crypto-shredding". Roots signed by Vault or KMS carry
`alg: "ecdsa-p256-sha256"`.

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

## Compliance, retention, keys, tenancy and operations

### Auditor packs per regime (templated layer)

`internal/compliance` is a separate templated layer over the record store: a registry of
versioned regime templates (`eu-ai-act@2026.09`, `soc2@2026.09`, `hipaa@2026.09`). Each control
states the requirement and its citation, the **evidence query** it runs over the ledger, and a
result:

- `pass`: the stated evidence criterion is met by records that verify. This never means
  "compliant".
- `gap`: the evidence is missing, failing, late, or the chain or its anchors are broken.
- `manual`: an organisational control that Ledger cannot evidence. The auditor must get this
  evidence from elsewhere. When there are no records at all, the result is never `pass`, and a
  test enforces this.

| Regime | Controls |
|---|---|
| EU AI Act | Art. 12(1), 12(2)(a)-(c); Art. 14(1), 14(4)(d)-(e), 14(5); **Art. 19(1)** log retention of at least 6 months; **Art. 26(1), (2), (5), (6)** deployer obligations; **Art. 72** post-market monitoring data; **Art. 73** serious-incident hook: each `ledger.incident.serious` (payload `incident_id`, `category`) needs a `*.incident.reported` with the same id within 15 days, or 2 days for `widespread`/`critical_infrastructure`, or 10 days for `death` |
| SOC 2 | CC6.1 (Warrant tokens and key management), CC6.2, CC6.3 (revocation/bounded tokens), CC6.6/6.8 (Warrant allow/deny), CC7.1 (policy versions), CC7.2 (anchors and verification), CC7.3, CC7.4 (incident → resolved), CC7.5 (signed backups), CC8.1 (every Gate run decided, plus approvals) |
| HIPAA | 164.312(b) audit controls, (c)(1) integrity, (c)(2) authentication of ePHI via anchors, (d) person/entity authentication, (a)(2)(iv) encryption; 164.308(a)(1)(ii)(D), (a)(7)(ii)(A); **164.316(b)(2)(i)**, which needs a 6-year retention policy on every chain in scope |

Every template ends with the integrity controls: hash-chain re-verification, offline
re-verification of every anchor receipt, and the root-key rotation history. The appendix lists
chain heads, signed roots, receipts, rotations, retention policies, legal holds and erasures.

```sh
ledger export --regime hipaa --from 2026-01-01 --to 2026-07-01 [--chain gate --chain warrant | --goal ID] --out pack
#   pack/report.json  report.html  report.pdf
ledger export --verify pack/report.pdf        # or report.json
```

The **document hash** is sha256 over the canonical JSON of the pack, with the hash and signature
fields left out. It is signed by the ledger key (Ed25519, or Vault/KMS through `LEDGER_SIGNER`).
The PDF is produced in pure Go with [go-pdf/fpdf](https://github.com/go-pdf/fpdf) (MIT) and is
byte-for-byte deterministic. It prints the hash and signature and stores them in the PDF metadata
(Subject/Keywords). It also embeds the signed pack as the attachment `report.json`, which
`--verify` extracts and checks. `ledger export --out DIR` without `--regime` still writes the
original `pack.json` + `narrative.html`.

### Retention, legal holds, crypto-shredding

Records are never deleted or edited. Retention policies, legal holds and erasures are records in
the `ledger` system chain (`ledger.retention.policy.set`, `ledger.hold.created`,
`ledger.hold.released`, `ledger.erasure`). This means they are hash-chained, anchored, exported
and backed up like any other record. Only ledger itself writes them: `POST /v1/records` refuses
these types (and `ledger.key.rotated`, `ledger.backup.created`) on the `ledger` chain with 403,
so an appender cannot, say, release a legal hold.

```sh
ledger retention set --chain '*' --regime hipaa --operator cco      # regime minimums: hipaa 6y, eu-ai-act 6m, soc2 1y
ledger retention status        # records past the minimum are *eligible* for shredding/archival, never deleted
ledger hold create --id lit-7 --reason "Doe v. Clinic" --chain clinic --operator counsel   # or --subject S / --all
ledger hold release --id lit-7 --reason "settled" --operator counsel
ledger erase --subject patient-1 --reason "DSR #88" --basis "GDPR Art. 17" --operator dpo [--override-retention TEXT]
```

**Envelope encryption (opt-in).** Set `LEDGER_DATA_KEY_DIR` on ledgerd and send
`"data_subject":"<id>"` with `POST /v1/records`. The payload is then stored as
`{"ledger_envelope":"ledger-envelope/v1","alg":"AES-256-GCM","key_id":"dk:…","nonce":…,"ciphertext":…}`.
The data key is per subject. The AAD binds the key id, the chain and the type. The subject id is
never stored; the key id is a hash of it. The record hash covers the ciphertext.

**Erasure.** `ledger erase` destroys the subject's data key. The store writes a tombstone first,
then overwrites and unlinks the key file. It then appends a `ledger.erasure` record. Tests show
that every chain still verifies afterwards and that neither the database nor the key directory
holds the plaintext. Decryption returns `ErrKeyDestroyed`, and the subject cannot be written to
again (409). Erasure is blocked in two cases:

- An active legal hold covers an affected chain or the subject. A hold cannot be overridden.
- The erasure would fall inside a regime's minimum retention. Here `--override-retention` lets the
  erasure proceed and records the justification.

### Key management

`internal/keys.Signer` signs roots and documents. It has three implementations:

- **Local Ed25519**: the existing key file or keyring. This is the default.
- **HashiCorp Vault Transit**: `LEDGER_SIGNER=vault`, `LEDGER_VAULT_ADDR`, `LEDGER_VAULT_TOKEN`,
  `LEDGER_VAULT_TRANSIT_KEY`, and optionally `LEDGER_VAULT_TRANSIT_MOUNT` and
  `LEDGER_VAULT_NAMESPACE`. The key type is ed25519 or ecdsa-p256.
- **AWS KMS**: `LEDGER_SIGNER=awskms`, `LEDGER_KMS_KEY_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN` and `LEDGER_KMS_ENDPOINT`. KMS has
  **no Ed25519 signing**, so the key must be `ECC_NIST_P256`/`SIGN_VERIFY` and roots are ECDSA
  P-256. The client calls the KMS JSON API directly with SigV4 signing and no AWS SDK; the SigV4
  code is tested against AWS's published example vector.

Roots signed by Vault or KMS carry `"alg":"ecdsa-p256-sha256"` and a PKIX public key. Ed25519
roots are unchanged and still have no `alg`. `VerifyRoot` and trust sets accept both algorithms.
Vault and KMS are tested against `httptest` fakes. The KMS fake recomputes and checks the SigV4
signature of every request. `DataKeyStore` holds the per-subject data keys; the only
implementation is a local directory. When `LEDGER_SIGNER` is Vault or KMS, ledgerd signs
`GET /v1/chains/{chain}/root` with it. Scheduled external anchoring still signs with the keyring.

### Multi-tenancy

To turn tenancy on, set `LEDGER_TOKENS=tokA=acme,tokB=globex,ops=*` (this replaces
`LEDGER_TOKEN`). The tenant comes from the bearer token.

- **Storage.** A tenant's chain `gate` is stored as `t/acme/gate`. The tenant is therefore part of
  the hashed `chain` field, and moving a record between tenants breaks its hash. The hash
  definition is unchanged.
- **Queries.** `chains.tenant` and `records.tenant` are derived by `BEFORE INSERT` triggers
  (migration 0500) and indexed. Scoped queries filter on these columns.
- **What a tenant can reach.** A tenant token only reaches its own chains: records, verify, root,
  anchors, replay and export. Names beginning with `t/` are rejected. A test shows no cross-tenant
  reads when two tenants use the same chain and goal names.
- **Default tenant.** Existing chains and tokens belong to `default`.
- **Operator routes.** The projection and incident routes read across chains, so they need an
  operator (`*`) token.
- **With the UI's roles.** A tenant token always takes the tenant path above. Any other
  credential (API token `ldg_…`, SSO session, `LEDGER_TOKEN`) is checked by the roles and then
  acts as an **operator across all tenants**, so give UI roles only to operator staff. Once
  tenancy is on, open mode never lets an unauthenticated request through.

### Backup and restore

```sh
ledger backup --out /backups/2026-09-24 --operator ops    # also appends ledger.backup.created
ledger restore --in /backups/2026-09-24 [--verify-only] [--allow-untrusted]
```

**Backup.** A backup is a logical export taken in one `REPEATABLE READ, READ ONLY` snapshot, with
no pg_dump. It writes:

- `manifest.json`
- `chains.json`
- `chains/*.jsonl`, with exact stored fields
- `anchor_receipts.jsonl`
- `anchors.jsonl`
- `keys.json`, which holds public keys only

The manifest lists the sha256 and size of every file and is signed by the ledger key.

**Restore.** Before inserting anything, restore checks:

- the manifest hash and signature
- that the signer is trusted (keyring or configured signer)
- every file hash, and that there are no unlisted files
- every hash chain against its manifest head
- every anchor receipt against the backed-up records

These checks catch a rewrite even when it was re-signed with a stolen key. Restore then inserts
everything in one transaction and never merges into existing chains. Afterwards it re-verifies.
Projections are derived data: run `ledger project --rebuild` after a restore.

### Performance

```sh
ledger bench --writers 16 --chains 64 --records 20000 --verify-n 1000000 --compare   # throwaway schema, dropped afterwards
LEDGER_TEST_DATABASE_URL=… LEDGER_BENCH_VERIFY_N=1000000 go test -run '^$' -bench . -benchtime 1x ./internal/bench
```

Setup: 4-vCPU Xeon @ 2.1 GHz container, local Postgres 16 on the same host, 256-byte payloads,
2-hop actor chains.

| Measurement | Before | After |
|---|---|---|
| Append, 16 writers across 64 chains | 2,013 rec/s (p50 4.6 ms, p99 54 ms) | **5,015–5,160 rec/s** (p50 2.7 ms, p99 8.2–8.7 ms) |
| Append, 16 writers on 1 chain (serialized by design) | 522 rec/s | **1,104 rec/s** |
| Verify a 1,000,000-record chain | 25.1–25.4 s = 39.4–39.8k rec/s, whole chain in memory | **14.3–15.1 s = 66–70k rec/s**, constant memory |

Bulk-loading the 1M-record chain for the verify benchmark takes about 57 s with COPY.

Fixes:

- Append pipelines its round trips into two batches, down from about 10 statements.
- Append no longer rewrites the goal row on every append. Doing so made writers on different
  chains of the same goal queue on its row lock. `goals.updated_at` is maintained by the
  projector.
- Verification streams 5,000-record pages by keyset. It prefetches the next page while hashing
  the current one, and hashes in parallel.
- Migration 0500 adds indexes for `(created_at, chain, seq)`, `(chain, created_at, seq)`, tenant
  queries and type.

CI runs the benchmarks with a small N.

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
with PKCE, sessions and CSRF protection,
incident review (JSON/HTML/Markdown), versioned regime templates (EU AI Act Art. 12/14/19/26/72/73,
SOC 2 CC6/CC7/CC8, HIPAA 164.308/312/316) rendered to signed JSON/HTML/PDF with anchor receipts,
chain verification and key-rotation history, retention policies + legal holds + crypto-shredding
erasure (opt-in AES-GCM payload envelopes), Signer interface with file / Vault Transit / AWS KMS
(ECDSA P-256) and mixed-algorithm root verification, multi-tenancy with tenant-bound chains,
signed logical backup/restore, `ledger bench` load test with measured numbers.

Not yet built (the "fully built version"):
- Transparency-log anchoring (Sigstore Rekor). RFC 3161 N-of-M, scheduled git commits and
  `verify --anchors` are built (see "External anchoring").
- Vault/KMS signers sign `/root`, packs and backups. Scheduled external anchoring and `keys rotate`
  still use the file keyring, and the rotation statement format is Ed25519-only. There is no
  data-key store in Vault or KMS yet, only the local directory, and no HSM/PKCS#11 signer.
- The live Vault Transit and AWS KMS signers are only tested against HTTP fakes, not against real
  services.
- CrewAI, AutoGen and OpenHands adapters are tested against stubs only (LangChain is tested for real).
- UI: no pagination on goals/approvals lists; anchor status in the UI checks head consistency only
  (receipt signatures are re-verified by `ledger verify --anchors`); no per-goal/per-chain access
  scoping (roles are global); no SCIM/group-claim role mapping; open mode is decided at startup.
- PDF output exists for the regime packs (`ledger export --regime`). The legacy
  `pack.json`/`narrative.html` export and `GET /v1/export` are still JSON/HTML/zip only. Regime
  packs are CLI-only, with no HTTP route yet.
- Projections: the query API loads the goal-filtered projection into memory per request (fine for
  thousands of rows per goal; no pagination on `/v1/goals` / `/v1/approvals` yet). Warrant calls
  without `goal_id` project goal-less approvals (linked to the goal only via token budgets and the
  incident review).
- Incident review scans every chain in memory to resolve cross-references (no ref index yet).
- Retention: "expiry" only reports records as eligible. There is no automatic tiering or
  archival to cold storage. Erasure works only on payloads written with `data_subject`, because
  plaintext records cannot be shredded without breaking the append-only rule.
- Tenancy: projections, incident review, retention/holds and the `ledger` system chain are not
  tenant-scoped (operator-only). Regime packs and backups cover all tenants. The CLI has no
  `--tenant` flag; use the physical `t/<tenant>/<chain>` names.
- Backup is a directory, not a single archive. Restore goes only into chains that do not exist
  yet; there is no incremental or point-in-time restore.
