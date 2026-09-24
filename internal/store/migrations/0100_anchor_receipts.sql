-- External anchoring receipts (stream: anchoring). Append-only, like records.
CREATE TABLE IF NOT EXISTS anchor_receipts (
    id           bigserial PRIMARY KEY,
    chain        text        NOT NULL,
    seq          bigint      NOT NULL,
    head         text        NOT NULL,
    root_digest  text        NOT NULL,  -- hex sha256 of anchor.Message(chain, seq, head): the TSA messageImprint
    key_id       text        NOT NULL,
    root_json    text        NOT NULL,  -- Ed25519-signed root exactly as anchored
    backend      text        NOT NULL,  -- e.g. rfc3161:freetsa, git, file
    kind         text        NOT NULL,  -- rfc3161 | git | file
    receipt      bytea       NOT NULL,  -- TSA TimeStampToken DER / committed bytes
    meta         jsonb       NOT NULL DEFAULT '{}',
    anchored_at  timestamptz NOT NULL,  -- TSA genTime / commit time / write time
    verified_at  timestamptz NOT NULL,  -- when ledgerd verified the receipt before storing it
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anchor_receipts_chain_idx ON anchor_receipts (chain, seq);

DROP TRIGGER IF EXISTS anchor_receipts_append_only ON anchor_receipts;
CREATE TRIGGER anchor_receipts_append_only BEFORE UPDATE OR DELETE ON anchor_receipts
    FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation();
DROP TRIGGER IF EXISTS anchor_receipts_no_truncate ON anchor_receipts;
CREATE TRIGGER anchor_receipts_no_truncate BEFORE TRUNCATE ON anchor_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_reject_mutation();

-- The legacy signed-root table (ledger anchor) was never protected; make it append-only too.
DROP TRIGGER IF EXISTS anchors_append_only ON anchors;
CREATE TRIGGER anchors_append_only BEFORE UPDATE OR DELETE ON anchors
    FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation();
