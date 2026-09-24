-- Optional client-supplied idempotency key for POST /v1/records: a retried append with the
-- same (chain, idempotency_key) returns the original record instead of creating a new one.
-- Additive and contract-compatible: existing callers that never set idempotency_key are
-- unaffected (NULL never collides with NULL under a partial unique index).
ALTER TABLE records ADD COLUMN IF NOT EXISTS idempotency_key text;
CREATE UNIQUE INDEX IF NOT EXISTS records_chain_idempotency_key_idx
    ON records (chain, idempotency_key) WHERE idempotency_key IS NOT NULL;
