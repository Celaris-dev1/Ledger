# Pricing

Ledger is open core. Everything that appends, verifies, replays, anchors or reviews a
decision chain — single-tenant `ledgerd`, the `ledger` CLI, external anchoring, projections,
incident review, retention/holds/erasure, backup/restore, and every SDK — is free, forever,
with no license required. See the README's "Built vs roadmap" and LICENSING sections for
exactly what that covers.

A small set of *compliance and operations* features on top of `ledgerd` require a paid,
offline license key. Nothing is ever deleted or hidden when a license lapses or was never
installed: those specific features just turn off (or, briefly, keep working with a warning
— see "Grace period" below) until a valid license is present again.

## Community — free

- `ledgerd` / `ledger` on any deployment (public, private, solo or commercial)
- Append, verify, replay, external anchoring (TSA/git/dir), receipt keys
- Single-tenant operation, retention and legal holds, crypto-shredding erasure
- Backup and restore, projections and cross-product incident review
- Python/TypeScript/Go SDKs

## Enterprise — contact sales

Unlocks, on top of Community:

- **Compliance evidence exports.** `ledger export --regime eu-ai-act|soc2|hipaa` — signed
  auditor packs (JSON/HTML/PDF) for EU AI Act, SOC 2 and HIPAA regimes.
- **External KMS/Vault root signing.** `LEDGER_SIGNER=vault|awskms`, for teams that must
  keep root signing keys in a managed HSM/KMS rather than on disk.
- **Multi-tenancy.** Running `ledgerd` with more than one tenant configured via
  `LEDGER_TOKENS`.

Custom seat counts, multi-year terms, and support SLAs — contact sales.

## How licensing works

A license is a small JSON document (customer, edition, features, seats, issued/expiry
dates) signed with Ed25519 and handed to you as one base64url token. Set it via
`LEDGER_LICENSE` (the token itself) or `LEDGER_LICENSE_FILE` (a path to a file holding it).
Verification is entirely offline: the token is checked against a vendor public key compiled
into the `ledgerd`/`ledger` binaries. There is no phone-home, no activation server, and no
telemetry — this works in air-gapped environments.

- `ledger license show` — current state, customer, edition, features, seats, expiry.
- `ledger license verify <token|file>` — verify a token offline and print what it grants.

**Grace period.** A license that has expired keeps unlocking its features, with a loud
warning, for 14 days — so a delayed renewal doesn't interrupt anyone's workflow. After that
it reads as expired and those features turn off (Community features are unaffected).

**Tampered or invalid tokens** are treated exactly like no license at all (Community), with
a warning logged — Ledger fails safe, never open, on a bad token, but it never fails your
build over one either.

See the README's LICENSING section for how a vendor issues keys with `tools/licensegen`.
