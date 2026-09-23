-- Domain schema from the Ledger spec. Rows here are projections / reference data;
-- the hash-chained source of truth is `records`.
CREATE TABLE IF NOT EXISTS operators (
    id           text PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('human','agent','service')),
    display_name text,
    model        text,
    model_version text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tools (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    version     text,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS goals (
    id                   text PRIMARY KEY,
    title                text,
    originating_human_id text,
    status               text NOT NULL DEFAULT 'open',
    first_record_id      uuid REFERENCES records(id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS goal_steps (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id     text NOT NULL REFERENCES goals(id),
    step_no     int  NOT NULL,
    description text,
    status      text NOT NULL DEFAULT 'proposed',
    record_id   uuid REFERENCES records(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (goal_id, step_no)
);

CREATE TABLE IF NOT EXISTS action_attempts (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id        text REFERENCES goals(id),
    step_id        uuid REFERENCES goal_steps(id),
    tool_id        text REFERENCES tools(id),
    action_hash    text NOT NULL,
    arguments      jsonb,
    outcome        text,
    policy_version text,
    record_id      uuid REFERENCES records(id),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verification_results (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_attempt_id uuid REFERENCES action_attempts(id),
    goal_id           text REFERENCES goals(id),
    verifier          text NOT NULL,
    passed            boolean NOT NULL,
    evidence          jsonb,
    record_id         uuid REFERENCES records(id),
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- Approvals bind to an exact action via action_hash: an approval for hash X never authorizes action Y.
CREATE TABLE IF NOT EXISTS approval_requests (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id      text REFERENCES goals(id),
    action_hash  text NOT NULL,
    requested_by text REFERENCES operators(id),
    decided_by   text REFERENCES operators(id),
    decision     text CHECK (decision IN ('approved','denied')),
    reason       text,
    record_id    uuid REFERENCES records(id),
    requested_at timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz
);
CREATE INDEX IF NOT EXISTS approval_requests_action_hash_idx ON approval_requests (action_hash);

CREATE TABLE IF NOT EXISTS budget_ledger (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id     text REFERENCES goals(id),
    operator_id text REFERENCES operators(id),
    resource    text NOT NULL,
    delta       numeric NOT NULL,
    balance     numeric,
    record_id   uuid REFERENCES records(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        text NOT NULL,
    detail      jsonb,
    record_id   uuid REFERENCES records(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION ledger_reject_mutation();

CREATE TABLE IF NOT EXISTS identity_facts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id text NOT NULL REFERENCES operators(id),
    fact        text NOT NULL,
    value       jsonb,
    asserted_by text,
    record_id   uuid REFERENCES records(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memory_items (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    goal_id     text REFERENCES goals(id),
    operator_id text REFERENCES operators(id),
    key         text NOT NULL,
    value       jsonb,
    record_id   uuid REFERENCES records(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
