-- Y12-T1: schema evolution bookkeeping.
--
-- * ddl_log: one row per DDL statement the provisioning engine runs, with
--   how long it took, how many lock retries it needed and how it ended, so an
--   operator can see what changed a table and what it cost. DDL text only:
--   values are always bound or archived, never written into a statement.
-- * attribute_alias: an attribute's old name, kept readable for a while
--   after a rename.
-- * data_step_run gains the paused and cancelled states and a rows_total
--   for progress.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ddl_log (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity text NOT NULL,
    statement_kind text NOT NULL,
    statement text NOT NULL,
    metadata_change_id bigint,
    actor uuid,
    started_at timestamptz NOT NULL,
    duration_ms integer NOT NULL CHECK (duration_ms >= 0),
    rows_touched bigint,
    attempts integer NOT NULL CHECK (attempts >= 1),
    outcome text NOT NULL CHECK (outcome IN ('ok', 'lock_timeout', 'failed'))
);

CREATE INDEX IF NOT EXISTS ddl_log_entity_started_idx ON ddl_log (entity, started_at DESC);

CREATE TABLE IF NOT EXISTS attribute_alias (
    entity text NOT NULL,
    old_name text NOT NULL,
    attribute_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (entity, old_name)
);

ALTER TABLE data_step_run DROP CONSTRAINT IF EXISTS ck_core_data_step_run_status;
ALTER TABLE data_step_run ADD CONSTRAINT ck_core_data_step_run_status CHECK (
    status IN ('queued', 'claimed', 'running', 'paused', 'cancelled', 'succeeded', 'failed',
               'abandoned')
) NOT VALID;
ALTER TABLE data_step_run VALIDATE CONSTRAINT ck_core_data_step_run_status;
ALTER TABLE data_step_run ADD COLUMN IF NOT EXISTS rows_total bigint;

GRANT SELECT, INSERT ON ddl_log TO attome_runtime;
GRANT SELECT ON ddl_log TO attome_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON attribute_alias TO attome_runtime;
GRANT SELECT ON attribute_alias TO attome_readonly;
