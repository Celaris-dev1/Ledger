-- Web UI / API access control (auth stream). None of these tables are part of the hash chain.
-- API tokens and session ids are stored only as SHA-256 hex digests.
CREATE TABLE IF NOT EXISTS auth_tokens (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    role        text NOT NULL CHECK (role IN ('admin','auditor','viewer','writer')),
    prefix      text NOT NULL,
    token_hash  text NOT NULL UNIQUE,
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS auth_users (
    id          text PRIMARY KEY,
    issuer      text NOT NULL,
    subject     text NOT NULL,
    email       text NOT NULL DEFAULT '',
    name        text NOT NULL DEFAULT '',
    role        text NOT NULL CHECK (role IN ('admin','auditor','viewer','writer')),
    disabled    boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_hash text PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('user','token')),
    subject_id   text NOT NULL,
    csrf         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions (expires_at);

-- Live stream wake-ups: every appended record notifies 'ledger_records' with "chain:seq".
-- Listeners still poll with a bounded cursor, so a missed notification only adds latency.
CREATE OR REPLACE FUNCTION ledger_notify_record() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('ledger_records', NEW.chain || ':' || NEW.seq);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS records_notify ON records;
CREATE TRIGGER records_notify AFTER INSERT ON records
    FOR EACH ROW EXECUTE FUNCTION ledger_notify_record();
