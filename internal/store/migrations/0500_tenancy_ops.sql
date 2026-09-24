-- Compliance/ops stream (0500-0599): multi-tenancy columns and performance indexes.
--
-- Tenancy: a tenant's chains are stored under the reserved name prefix "t/<tenant>/<chain>", so
-- the tenant is part of the hashed `chain` field (moving a record between tenants breaks its hash)
-- without changing the hash definition. The `tenant` columns are derived from the name by
-- BEFORE INSERT triggers (never by UPDATE: records stay append-only) and exist for indexed,
-- tenant-filtered queries. Every existing chain belongs to tenant 'default' (column default).
ALTER TABLE chains  ADD COLUMN IF NOT EXISTS tenant text NOT NULL DEFAULT 'default';
ALTER TABLE records ADD COLUMN IF NOT EXISTS tenant text NOT NULL DEFAULT 'default';

CREATE OR REPLACE FUNCTION ledger_tenant_of(chain text) RETURNS text AS $$
    SELECT CASE WHEN chain LIKE 't/%/%' AND split_part(chain, '/', 2) <> ''
                THEN split_part(chain, '/', 2) ELSE 'default' END
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION ledger_records_set_tenant() RETURNS trigger AS $$
BEGIN
    NEW.tenant := ledger_tenant_of(NEW.chain);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS records_set_tenant ON records;
CREATE TRIGGER records_set_tenant BEFORE INSERT ON records
    FOR EACH ROW EXECUTE FUNCTION ledger_records_set_tenant();

CREATE OR REPLACE FUNCTION ledger_chains_set_tenant() RETURNS trigger AS $$
BEGIN
    NEW.tenant := ledger_tenant_of(NEW.name);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS chains_set_tenant ON chains;
CREATE TRIGGER chains_set_tenant BEFORE INSERT ON chains
    FOR EACH ROW EXECUTE FUNCTION ledger_chains_set_tenant();

-- Indexes for the hot read paths measured by `ledger bench`:
--   GET /v1/records ordered by (created_at, chain, seq), optionally per chain or tenant,
--   compliance exports by time window, and tenant-scoped goal replay.
CREATE INDEX IF NOT EXISTS records_created_idx        ON records (created_at, chain, seq);
CREATE INDEX IF NOT EXISTS records_chain_created_idx  ON records (chain, created_at, seq);
CREATE INDEX IF NOT EXISTS records_tenant_created_idx ON records (tenant, created_at, chain, seq);
CREATE INDEX IF NOT EXISTS records_tenant_goal_idx    ON records (tenant, goal_id, created_at, seq);
CREATE INDEX IF NOT EXISTS records_type_idx           ON records (type, created_at);
CREATE INDEX IF NOT EXISTS chains_tenant_idx          ON chains (tenant, name);
