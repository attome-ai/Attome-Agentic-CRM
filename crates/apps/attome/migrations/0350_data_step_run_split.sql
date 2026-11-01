-- A1-T8: splitting one text attribute into several runs as a data step run
-- of kind 'split': it backfills the target attributes in keyset batches from
-- the run's cursor, and pauses, resumes and is cancelled like the others.
SET LOCAL lock_timeout = '5s';

ALTER TABLE data_step_run DROP CONSTRAINT IF EXISTS ck_core_data_step_run_kind;
ALTER TABLE data_step_run ADD CONSTRAINT ck_core_data_step_run_kind CHECK (
    kind = ANY (ARRAY['copy', 'convert', 'map_values', 'set_default', 'retype', 'archive',
                      'orphan_scan', 'partition', 'split'])
);
