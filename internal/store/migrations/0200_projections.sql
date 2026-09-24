-- Projections stream (0200-0299): bookkeeping for the incremental, rebuildable projector
-- (internal/projection) plus additive columns on the spec's domain tables. Everything
-- here is derived data and may be deleted and rebuilt from `records` at any time.
CREATE TABLE IF NOT EXISTS projection_meta (
    id         int PRIMARY KEY CHECK (id = 1),
    version    int NOT NULL,
    rebuilt_at timestamptz
);

CREATE TABLE IF NOT EXISTS projection_cursors (
    chain      text PRIMARY KEY,
    seq        bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Every op derived from a record; groups are recomputed from their ops.
CREATE TABLE IF NOT EXISTS projection_ops (
    op_id text PRIMARY KEY,
    grp   text NOT NULL,
    key   text NOT NULL,
    data  jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS projection_ops_grp_idx ON projection_ops (grp);

ALTER TABLE action_attempts ADD COLUMN IF NOT EXISTS attempt_key text;
ALTER TABLE action_attempts ADD COLUMN IF NOT EXISTS result_record_id uuid REFERENCES records(id);
CREATE UNIQUE INDEX IF NOT EXISTS action_attempts_attempt_key_idx ON action_attempts (attempt_key);

ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS request_key text;
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS decision_record_id uuid REFERENCES records(id);
CREATE UNIQUE INDEX IF NOT EXISTS approval_requests_request_key_idx ON approval_requests (request_key);

-- Every decision, including ones that do not match their request's action_hash
-- (matched=false): those never satisfy the request.
CREATE TABLE IF NOT EXISTS approval_decisions (
    id          uuid PRIMARY KEY,
    request_key text NOT NULL,
    goal_id     text REFERENCES goals(id),
    action_hash text NOT NULL,
    decision    text NOT NULL,
    decided_by  text REFERENCES operators(id),
    reason      text,
    matched     boolean NOT NULL,
    record_id   uuid REFERENCES records(id),
    decided_at  timestamptz
);
CREATE INDEX IF NOT EXISTS approval_decisions_request_idx ON approval_decisions (request_key);

ALTER TABLE budget_ledger ADD COLUMN IF NOT EXISTS grp text;
ALTER TABLE budget_ledger ADD COLUMN IF NOT EXISTS position int;
ALTER TABLE budget_ledger ADD COLUMN IF NOT EXISTS entry_kind text;
ALTER TABLE budget_ledger ADD COLUMN IF NOT EXISTS overspent boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS budget_ledger_grp_idx ON budget_ledger (grp);
