-- A18-T1: the recycle bin's ledger. One row per record removed by a soft
-- delete (dependents cascaded with it stay in cascade_deactivation), with who,
-- when, why and the operation it belonged to, so a whole action can be undone.
-- restored_at / purged_at close the row; at most one open row per record.
CREATE TABLE IF NOT EXISTS deletion (
    id uuid PRIMARY KEY,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    deleted_by uuid,
    deleted_at timestamptz NOT NULL DEFAULT now(),
    reason text,
    operation_kind text NOT NULL CHECK (operation_kind IN
        ('request', 'agent', 'flow', 'bulk', 'import', 'merge', 'portal', 'migration')),
    operation_id text NOT NULL,
    restored_at timestamptz,
    restored_by uuid,
    purged_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS deletion_open
    ON deletion (entity, record_id) WHERE restored_at IS NULL AND purged_at IS NULL;
CREATE INDEX IF NOT EXISTS deletion_operation ON deletion (operation_id);
CREATE INDEX IF NOT EXISTS deletion_recent ON deletion (deleted_at DESC);

-- Per-entity bin rules; an entity with no row takes the defaults.
CREATE TABLE IF NOT EXISTS bin_setting (
    entity text PRIMARY KEY,
    require_reason boolean NOT NULL DEFAULT false,
    retention_days integer CHECK (retention_days IS NULL OR retention_days > 0),
    alert_threshold integer NOT NULL DEFAULT 100 CHECK (alert_threshold > 0),
    hard_delete_needs_approval boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 1
);

GRANT SELECT, INSERT, UPDATE ON deletion, bin_setting TO attome_runtime;
GRANT SELECT ON deletion, bin_setting TO attome_readonly;
