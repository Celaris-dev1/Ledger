-- Receipt key enrollment: the trust keyring for stack-receipt/v1 envelopes (see
-- docs/receipt-spec.md, internal/receipt). Products register their signing public keys here so
-- `ledger incident` and `ledger verify-receipt` can report trusted:true for a receipt signed by
-- an enrolled, unrevoked key, and reject one signed by a key revoked before the receipt's
-- issued_at.
--
-- Not part of the hash chain: this is operator-managed configuration, not an append-only event
-- log. `tenant` follows the same convention as chains/records (0500_tenancy_ops.sql): every
-- existing row belongs to tenant 'default', and a tenant's enrollment is independent of others'.
CREATE TABLE IF NOT EXISTS receipt_keys (
    key_id      text NOT NULL,
    tenant      text NOT NULL DEFAULT 'default',
    product     text NOT NULL,
    alg         text NOT NULL,
    public_key  text NOT NULL, -- base64: raw 32 bytes Ed25519, or PKIX DER for ECDSA
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    enrolled_by text NOT NULL DEFAULT '',
    revoked_at  timestamptz,
    reason      text NOT NULL DEFAULT '', -- revocation reason; empty while unrevoked
    PRIMARY KEY (tenant, key_id)
);
CREATE INDEX IF NOT EXISTS receipt_keys_product_idx ON receipt_keys (tenant, product);
