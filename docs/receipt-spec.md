# stack-receipt/v1

A signed, product-agnostic envelope any product in the stack (Gate, Proof, Ledger, Warrant,
Harbour, Bench) can emit to attest to a decision, an effect, or a verification, and that Ledger
stores, verifies, and links across products for the [incident report](#incident-linking).

This is deliberately a *thin* layer on top of each product's own Ledger records (which already
carry `chain`, `goal_id`, `actor_chain`, hash-chained `prev_hash`/`hash`, etc. — see each
product's `internal/ledger` client). A stack-receipt is evidence *about* something a product did;
it is not a replacement for that product's own append-only chain. In practice a product signs one
of these at the same point it already calls `ledger.Append`, using the appended record's
canonical-JSON payload hash as `payload_hash`.

## Envelope

```json
{
  "version": "stack-receipt/v1",
  "product": "gate",
  "kind": "gate.verdict",
  "goal_id": "goal-1",
  "actor_chain": [
    {"kind": "human", "id": "alice"},
    {"kind": "agent", "id": "gate-ci", "model": "gate"}
  ],
  "subject": "run-1",
  "payload_hash": "<hex sha256>",
  "links": [
    {"product": "warrant", "id": "tok-1", "hash": "<hex sha256>"}
  ],
  "issued_at": "2026-01-01T00:00:00Z",
  "signer_key_id": "ed25519:df5b205f12c47fae",
  "signature": "<base64>"
}
```

| Field           | Type            | Required | Meaning |
|-----------------|-----------------|----------|---------|
| `version`       | string          | yes      | Exactly `"stack-receipt/v1"`. |
| `product`       | string          | yes      | One of `gate`, `proof`, `ledger`, `warrant`, `harbour`, `bench`. |
| `kind`          | string          | yes      | Product-defined event name, e.g. `gate.verdict`, `warrant.decision`, `harbour.effect`, `proof.capture`, `proof.certificate`, `bench.score`. |
| `goal_id`       | string          | no       | The cross-product goal this receipt belongs to, when known. |
| `actor_chain`   | `Actor[]`       | yes      | Non-empty; `actor_chain[0].kind` must be `"human"` (same rule as Ledger's own `Record.ActorChain`). |
| `subject`       | string          | no       | What the receipt is about: a run id, token id, effect id, capture id, etc. |
| `payload_hash`  | hex sha256      | yes      | `sha256hex(canonical_json(payload))` of the payload this receipt attests to (the *same* canonicalization Ledger uses for its own record hash chain — see `internal/canon`). The payload itself is not part of the envelope; only its hash is, so the receipt stays small and payloads can be arbitrarily large or already stored elsewhere (e.g. as the Ledger record's own `payload`). |
| `links`         | `Link[]`        | no       | Other products' record/receipt ids this receipt depends on or is evidence about, e.g. a Harbour effect receipt linking to the Warrant token that authorised it. |
| `issued_at`     | RFC3339 UTC     | yes      | When the receipt was signed. |
| `signer_key_id` | string          | yes      | `"ed25519:"+hex(sha256(pubkey)[:8])` (or `"ecdsa-p256:..."`), matching Ledger's `keys.KeyIDFor`. |
| `signature`     | base64          | yes      | Ed25519 (or ECDSA P-256) signature over the canonical JSON of the envelope with `signature` set to `""`. |

`Actor` is `{kind, id, model?, model_version?}`; `Link` is `{product, id, hash?}`.

## Canonicalization and signing

The signed bytes are the **canonical JSON** (RFC 8785-style: object keys sorted, no
insignificant whitespace, no HTML-escaping) of the envelope with `signature` cleared to `""`
(and `signer_key_id` already filled in — it's part of what's signed, so a receipt can't be
re-attributed to a different key after signing). This is exactly Ledger's existing canonical-JSON
encoder (`internal/canon.CanonicalBytes`), reused so every product produces byte-identical
canonical forms without depending on Ledger's binary.

`payload_hash` uses the same canonicalization: `sha256hex(canonical_json(payload))` (Ledger's
`internal/canon.Hash("", payload)` with an empty `prev`, since a receipt's payload hash is not
itself chained).

Signature algorithm is Ed25519 (default) or ECDSA P-256 (`ecdsa-p256-sha256`, ASN.1 DER signature
over `sha256(message)`) — the same two algorithms Ledger's key backends already support
(`internal/keys`), so a product can sign with a local key, Vault Transit, or AWS KMS via the same
`keys.Signer` interface.

## Reference implementation

The canonical implementation is `internal/receipt` in this repo (`Envelope`, `Sign`, `Verify`,
`PayloadHash`). It depends only on `internal/canon` and `internal/keys`, so other repos may vendor
or reimplement the same ~150 lines against the conformance vectors below rather than importing
this module. Each product's copy should mirror `internal/receipt/receipt.go` field-for-field.

## Conformance test vectors

`testdata/receipts/` holds fixed, deterministic fixtures every product's emitter tests validate
against (copied into that product's repo — no cross-repo build dependency):

- `testdata/receipts/valid/key.json` — the fixed Ed25519 test key (`public_key`, base64) and its
  `key_id`, used to verify every fixture below.
- `testdata/receipts/valid/gate-verdict.json`, `valid/warrant-decision.json` — well-formed,
  correctly signed envelopes.
- `testdata/receipts/invalid/bad-signature.json` — structurally valid, signature does not verify.
- `testdata/receipts/invalid/bad-version.json` — unsupported `version`.
- `testdata/receipts/invalid/missing-human-actor.json` — `actor_chain[0].kind != "human"`.
- `testdata/receipts/invalid/malformed-payload-hash.json` — `payload_hash` is not 64 hex chars.

Regenerate with `go test ./internal/receipt/... -run TestConformanceVectors -v` (it both writes
and immediately re-verifies every vector, so the fixtures can never drift from what
`internal/receipt` actually accepts).

A conformant verifier must: accept every fixture under `valid/` when checked against
`valid/key.json`, and reject every fixture under `invalid/` (either at JSON-structure validation
or at signature verification).

## Storage and verification (Ledger)

Ledger stores stack-receipts as the `payload.receipt` field of an ordinary Ledger record (so they
ride the existing hash-chained, tenant-scoped storage — no new table), typically alongside the
raw payload the receipt attests to. `ledger verify-receipt` (see `cmd/ledger`) verifies a receipt
read from a file, stdin, or `--record ID` (pulling `payload.receipt` out of a stored record) against
a configured trusted key/keyring, exit 0 on a valid signature and 1 otherwise. `POST
/v1/records` accepts `payload.receipt` as any other payload field; there's no separate receipt
endpoint.

## Incident linking

`ledger incident --goal ID` (see `internal/incident`) already joins every product's chain records
for a goal by `goal_id` plus cross-references in payloads. It additionally now walks any
`payload.receipt` on those records: verifies each receipt's signature against the configured
keyring, resolves its `links` to the records they name (by id, falling back to matching
`payload_hash`), and reports per-receipt verification status plus the whole chain of custody —
who authorised (Warrant) → what ran (Harbour) → what it read (Proof) → what verified it
(Gate/Bench) — with every signature and hash checked, not just Ledger's own append-only chain
integrity. See `internal/incident.Report.Receipts` and the HTML/JSON output.

## Emission points

Each product emits a `stack-receipt/v1` at the point it already talks to Ledger, signing over the
payload it's about to (or just did) append:

- **Warrant**: token issuance and call allow/deny decisions (`kind: "warrant.decision"`).
- **Harbour**: effect results, i.e. the tool call actually committed (`kind: "harbour.effect"`),
  linked to the Warrant decision (if any) that authorised it.
- **Gate**: run verdicts (`kind: "gate.verdict"`).
- **Proof**: fetch captures and signed manifests/certificates (`kind: "proof.capture"` /
  `"proof.certificate"`).
- **Bench**: task run scores (`kind: "bench.score"`), linked to the Gate/Ledger history it read.

Extending, not rewriting: each product's existing `internal/ledger` HTTP client is unchanged;
receipt signing is an additional step alongside the existing `Append` call, using whatever
`keys.Signer` (or an equivalent local Ed25519 key) that product already has configured, or a
freshly generated one if none is configured yet.
