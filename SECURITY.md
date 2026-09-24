# Security

Ledger exists to prove what happened in a way that shows when someone tampers with it. This
document covers what it defends against, where its trust boundaries are, what "verified"
proves and what it does not, and how to report a vulnerability.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's "Report a vulnerability"
(security advisories) on this repository. Do not open a public issue. Include a reproduction,
the affected version or commit, and the impact. We aim to acknowledge reports within 3 working
days. We credit reporters unless they ask us not to.

## Threat model

| Actor | Assumed capability | What Ledger guarantees |
|---|---|---|
| Agent / SDK client (writer token) | Appends records to chains | Cannot alter, reorder or delete existing records. Cannot drop the originating human from `actor_chain`. Cannot write to another tenant's chains when it holds a tenant token. |
| Reader roles (viewer/auditor) | Read the API and UI | Cannot write. Cannot manage tokens or users. Viewers cannot export. |
| Other tenants | Hold their own tenant token | Cannot name, read, verify or append to another tenant's chains. The tenant is part of the hashed chain name (`t/<tenant>/<chain>`). |
| Network attacker / hostile web page | Sends requests with the victim's browser cookies | CSRF tokens, `SameSite` cookies and Origin checks guard every state-changing UI action. A strict CSP (no inline script) and `frame-ancestors 'none'` apply. Login redirects only go to local paths. |
| Database administrator / compromised DB role | Can run arbitrary SQL, including disabling triggers | **Detection, not prevention**: any edit, reorder or deletion inside an anchored prefix is detected by `ledger verify --anchors`, against a key and anchors the DBA does not control. |
| Holder of the root signing key | Can sign roots and backups | Can sign a rewritten history, but cannot backdate RFC 3161 timestamps or rewrite external anchors (git remote, TSA tokens) that were already issued. |
| Local user on an SDK host | Shares `/tmp` | SDK spools live in a per-user `0700` directory as `0600` files. They never follow symlinks, and a spool owned by someone else or writable by others is refused. |

Out of scope: confidentiality against the database administrator (use payload envelope
encryption with `data_subject`, and keep data keys off the database host); denial of service by
authenticated principals; a compromised host running `ledgerd` (it holds the signing key unless
you use Vault/KMS).

## Trust boundaries

1. **HTTP API and UI** (`ledgerd`). Every route checks a role (see `internal/auth`). Tenant
   tokens (`LEDGER_TOKENS`) reach only the tenant-scoped record routes. The projection,
   incident, stream and UI routes need an RBAC principal (API token or SSO session). Open mode
   (no credentials configured) is for local development only and is refused whenever
   multi-tenancy is configured.
2. **Postgres.** Triggers reject `UPDATE`, `DELETE` and `TRUNCATE` on `records`,
   `anchor_receipts`, `anchors` and `audit_events` for the application role. A superuser can
   bypass them, and that is why the hash chain and anchors exist.
3. **Signing keys.** Root and backup signatures come from a local Ed25519 keyring, Vault
   Transit or AWS KMS. Signatures from KMS and Vault are re-verified locally before use.
   Verifiers only need public keys. Backups and exports contain public keys only.
4. **External anchors.** RFC 3161 TSAs (N-of-M quorum), a git remote, or an anchor directory.
   They are trusted only through their own signatures and your trust bundle.
5. **SDK hosts.** The spool holds unsent evidence and is sent using the host's token.

## What "verified" proves

`GET /v1/chains/{c}/verify` and `ledger verify` recompute every record hash,
`sha256(prev_hash + "\n" + canonical_json(record without hash/prev_hash))`. They also check
that `seq` is contiguous from 1, that each `prev_hash` links to the previous hash, and that the
chain's head pointer matches. On the database path, each stored `actor_chain`/`payload` must be
byte-identical to its canonical form. Otherwise duplicate keys or reformatting could show
different text from the text that was hashed. Appends also reject payloads with duplicate
object keys.

A passing plain `verify` proves only that the records are **internally consistent**. Someone
with database access can rewrite a whole chain and recompute every hash, or delete records from
the end and move the head back. Plain verification cannot tell.

`ledger verify --anchors` (with a keyring or trust bundle) also proves that every externally
anchored `(seq, head)` is still a prefix of the chain. So nothing at or before the last anchored
record has been altered, reordered or removed since it was anchored. With RFC 3161 receipts
from a trusted TSA, it also proves that the head existed at the TSA's `genTime`.

**It does not prove:**

- That records **after the last anchor** are genuine, or that none were removed from the
  end. Anchor often (`LEDGER_ANCHOR_EVERY`/`LEDGER_ANCHOR_INTERVAL`).
- That anchors were not **suppressed**. If every receipt is deleted from the database and no
  external copy is consulted, verification warns "no anchors recorded" but does not fail. Keep
  anchors outside the database (a git remote or anchor dir) and check against them.
- That a record's **content is true**. Ledger proves what was written and when, not that the
  writer was honest. `actor_chain` identities are whatever the authenticated writer asserted.
  Ledger does no Unicode normalisation, so homoglyph actor ids are distinct ids.
- That a root is trusted, **if no keyring or trust set is configured**. Roots are then only
  checked against the public key embedded in them, and a warning says so. The same applies to
  a backup restored with `--allow-untrusted` or without a keyring.
- **Confidentiality** of payloads. Hashes cover ciphertext when envelope encryption is used.
  Crypto-shredding removes the key, and the chain still verifies.

The in-browser check on record pages uses an independent JavaScript implementation of the
canonical encoding. It re-derives the hash from the record the server sent. It proves the page
matches its hash, not that the server sent you the whole chain.

## Hardening checklist

- Set `LEDGER_AUTH=on` in production. Use per-client API tokens or SSO, not the shared
  `LEDGER_TOKEN`.
- Serve over TLS (sets `Secure` cookies and HSTS). Set `LEDGER_SECURE_COOKIES=1` behind a
  TLS-terminating proxy.
- Run `ledgerd` as a non-superuser database role that owns no triggers.
- Configure a keyring (`LEDGER_KEYRING_DIR`) or KMS/Vault signer. Distribute the public keys to
  verifiers out of band.
- Anchor to at least one external witness, such as RFC 3161 with a quorum or a git remote, and
  run `ledger verify --anchors` from a machine that does not trust the database.
- Restore backups with a keyring configured, so the manifest signer is checked against trusted keys. Avoid `--allow-untrusted`.
