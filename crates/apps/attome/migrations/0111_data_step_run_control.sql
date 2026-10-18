-- Y12-T5: a data step run can be paused between batches and resumed from
-- its cursor; started_at (its first claim) dates its progress for the ETA.
ALTER TABLE data_step_run DROP CONSTRAINT IF EXISTS ck_core_data_step_run_status;
ALTER TABLE data_step_run ADD CONSTRAINT ck_core_data_step_run_status CHECK (
    status = ANY (ARRAY['queued', 'claimed', 'running', 'paused', 'succeeded', 'failed', 'abandoned'])
);

ALTER TABLE data_step_run ADD COLUMN IF NOT EXISTS started_at timestamptz;
