# Forge It: a public challenge to Ledger's offline verifier

Ledger's job is to make an agent system's decision log tamper-*evident*: not "nobody can edit
it" (a database administrator plainly can), but "if anyone edits it, the edit is detectable" —
even by someone who only has an exported bundle, no access to the database, and no network
connection.

This page is a standing challenge: take the sample bundle below, forge any change you like, and
see whether `ledger-verify` still says the bundle is OK. If you can make it pass while the
content it certifies is not what actually happened, that is a real finding — please report it
(see SECURITY.md).

## Threat model

**What we are defending against.** Someone holding the exported bundle file — an auditor, a
counterparty, a regulator, an attacker who exfiltrated it, or an insider with full database
access at the time it was exported — tries to convince `ledger-verify` that the chain of events
it describes is something other than what was actually recorded, without leaving the tampering
detectable to a verifier who:

- has **only** the bundle file (no database, no network, no Ledger account);
- trusts nothing but whatever public keys are embedded in the bundle itself and, if you want
  operator-controlled trust rather than "trust the file's own claims," a `trust.json` you obtained
  independently (e.g. published alongside the bundle, or pinned from a prior audit).

**What counts as a win for the forger.** Any of the following, undetected by `ledger-verify`:

- **modify** a record's payload, actor chain, type, or any other field, after the fact;
- **reorder** records within a chain;
- **delete** a record from the middle or end of a chain;
- **insert** a record that was never actually appended;
- **swap** the root signature for one from a different (untrusted) key;
- **swap** the trusted key set (`trust.json`) so an untrusted signer is accepted;
- **truncate the tail** — drop the last N records — *after* the point some external witness
  (a TSA token, a pushed git commit, a `trust.json`-trusted root) attests to, without detection.

If your change makes `ledger-verify` print `OK` (exit code 0) for a chain whose actual content
differs from what the sample was built to represent, you have forged it.

## What's out of scope

This challenge is about the **verifier**, not about compromising the things it trusts. The
following are explicitly out of scope — they are pre-conditions the whole design assumes away,
not bugs in `ledger-verify`:

- **Compromise of the signing key itself.** If you have the private key that signed a chain's
  root, you can sign a new, self-consistent lie and it will verify — because it *is* validly
  signed by a key the verifier was told to trust. Key custody (HSM, KMS, Vault Transit, offline
  cold storage, rotation) is a separate problem; see `internal/keys` and the "External anchoring"
  and "Key rotation" sections of the README.
- **Compromise of a trusted RFC 3161 TSA**, or of the CA that issued its certificate. If a TSA
  itself will backdate or forge tokens for you, no client-side verification catches that; you're
  attacking the timestamping authority, not Ledger. (This is why the anchoring backends support
  N-of-M TSAs plus git and a local directory: no single third party is a single point of trust.)
- **Truncation of history that was never externally anchored in the first place.** See below —
  this is the one gap we document rather than paper over.

## The honest gap: truncating after the last anchor

`ledger-verify` (like `ledger verify --anchors`) can only prove a chain's current state is
*consistent with, and extends,* whatever external evidence the bundle carries: a root signed by a
trusted key, an RFC 3161 token, a pushed git commit. If the last record in a bundle sits **after**
the last point anything external attested to, deleting everything from there to the end is
**not detectable from the bundle alone** — there is nothing left to notice it's missing.

Concretely: if a chain has 10 records and was last anchored at seq 7, an attacker who can edit the
underlying database (or hand-forge a bundle from records they control) can truncate to seq 7 and
recompute nothing, because seq 7's hash is unchanged; `ledger-verify` will report the bundle as
`OK` for a 7-record chain that "should" have had 10. It correctly reports the anchored prefix as
intact — because it is — but it cannot know that 3 more records used to exist. Nothing can, from
this evidence alone: a hash chain proves order and integrity of what's present, not the
non-existence of what's absent.

This is why the README frames anchoring the way it does ("a compromised DB administrator cannot
*silently* rewrite history") rather than claiming truncation is always caught: catching it
requires an external witness *after* the point you want to protect. In practice this means:
anchor often (`LEDGER_ANCHOR_EVERY` / `LEDGER_ANCHOR_INTERVAL`), and treat "how far behind is the
last anchor" as a monitored number, not an afterthought — a bundle whose tail sits far past its
last anchored seq is itself a signal worth investigating even when `ledger-verify` says OK.
`internal/bundle/bundle_test.go`'s `TestTamperTruncateTail` truncates *past* the last anchor and
confirms it's caught; there is deliberately no test claiming to catch truncation *before* it,
because that would be a false claim.

## The sample bundle

`docs/forge-it/sample-bundle.tar` is a small, fictional 5-record chain (a page-publishing
workflow) built and signed deterministically by `tools/forge-it-sample` — regenerate it any time
with:

```sh
scripts/forge-it-sample.sh
```

It contains **no private key material**. The Ed25519 signing key is generated in memory, used
once to sign the chain's root, and discarded; only the public key (embedded in the signed root,
inside the bundle) ships. `docs/forge-it/README.txt` (also generated) states the exact chain,
root, and key id for that run, and running the script again reproduces byte-identical output —
the generator uses a fixed seed and fixed timestamps for exactly this reason.

Verify the untouched sample:

```sh
go build -o ledger-verify ./cmd/ledger-verify
./ledger-verify docs/forge-it/sample-bundle.tar
```

Now try to forge it. Some starting points (all of these are caught — try to find one that isn't):

```sh
mkdir -p /tmp/forge && cd /tmp/forge
tar xzf /path/to/sample-bundle.tar
python3 -c "
import json
with open('chains/forge-it-sample/records.json') as f: recs = json.load(f)
recs[2]['payload'] = {'tool': 'cms.publish_draft', 'args': {'page': 'a-different-page'}}
with open('chains/forge-it-sample/records.json', 'w') as f: json.dump(recs, f)
"
tar czf ../forged.tar .
../ledger-verify ../forged.tar   # expect: FAILED, naming the exact seq and reason
```

## Rules

1. Start from `docs/forge-it/sample-bundle.tar` (or a bundle you build yourself with
   `ledger bundle`) and produce a modified `.tar` that `ledger-verify` (unmodified, at this
   repository's HEAD) reports `OK` for, where the content differs from what the original
   represented — a record modified, reordered, deleted, or inserted, or a signature/key swapped.
2. Truncation only counts within scope if it drops records at or before the last externally
   anchored seq (see "the honest gap" above) — truncating only the unanchored tail is the known,
   documented gap, not a finding.
3. Don't modify `ledger-verify`, `internal/anchoring`, or `internal/bundle` themselves — the
   challenge is against the shipped verifier, not a weakened copy of it.
4. Report a real finding via SECURITY.md with the forged bundle attached (or a script that
   produces it) and the exact `ledger-verify` output showing it passing.

## Why re-use `internal/anchoring.VerifyChain`

`cmd/ledger-verify` does not reimplement verification: `internal/bundle.Verify` calls the exact
same `anchoring.VerifyChain` function that backs `ledger verify --anchors` and
`GET /v1/chains/{chain}/anchors?verify=1`. A bundle is just that function's inputs (records,
receipts, trust set, TSA roots) packaged into one file instead of read live from Postgres. This
means there is exactly one verification code path in the whole project, tested once
(`internal/anchoring/*_test.go`, `internal/bundle/bundle_test.go`) and exercised from three
different front doors — not three parallel implementations that could quietly drift apart.
