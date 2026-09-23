-- Hash-chained, append-only record log.
CREATE TABLE IF NOT EXISTS chains (
    name        text PRIMARY KEY,
    head_seq    bigint NOT NULL DEFAULT 0,
    head_hash   text   NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS records (
    id              uuid PRIMARY KEY,
    chain           text NOT NULL REFERENCES chains(name),
    seq             bigint NOT NULL,
    type            text NOT NULL,
    goal_id         text,
    actor_chain     json NOT NULL,   -- json (not jsonb): preserves the exact canonical text that was hashed
    policy_version  text,
    payload         json NOT NULL,
    created_at      timestamptz NOT NULL,
    prev_hash       text NOT NULL,
    hash            text NOT NULL UNIQUE,
    UNIQUE (chain, seq)
);
CREATE INDEX IF NOT EXISTS records_goal_idx ON records (goal_id, created_at, seq);

CREATE OR REPLACE FUNCTION ledger_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'ledger: % is append-only (% rejected)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS records_append_only ON records;
CREATE TRIGGER records_append_only BEFORE UPDATE OR DELETE ON records
    FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation();
DROP TRIGGER IF EXISTS records_no_truncate ON records;
CREATE TRIGGER records_no_truncate BEFORE TRUNCATE ON records
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_reject_mutation();

CREATE TABLE IF NOT EXISTS anchors (
    id          bigserial PRIMARY KEY,
    chain       text NOT NULL,
    seq         bigint NOT NULL,
    head        text NOT NULL,
    signature   text NOT NULL,
    public_key  text NOT NULL,
    anchored_at timestamptz NOT NULL DEFAULT now()
);
