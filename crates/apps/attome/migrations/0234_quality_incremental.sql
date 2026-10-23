-- L2-T3: incremental data quality scoring. Per-record scores are kept only
-- for entities that turn record scoring on; the rescan state keeps the
-- fingerprint of what an entity's scores depend on (rules, weights,
-- threshold, required attributes), so a change queues one rescan.
SET LOCAL lock_timeout = '5s';

ALTER TABLE quality_target ADD COLUMN IF NOT EXISTS record_scoring boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS quality_rescan_state (
    entity text PRIMARY KEY,
    fingerprint text NOT NULL,
    queued_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

GRANT SELECT, INSERT, UPDATE, DELETE ON quality_rescan_state TO attome_runtime;
GRANT SELECT ON quality_rescan_state TO attome_readonly;
