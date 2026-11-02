-- A1-T9: extracting repeating attributes into a child entity runs as a data
-- step run of kind 'extract_child' (each parent's non-empty values copied
-- into child rows), and turning a lookup into a many-to-many relationship as
-- one of kind 'link_copy' (each set lookup copied as a link); both go in
-- keyset batches from the run's cursor, and pause, resume and are cancelled
-- like the others.
SET LOCAL lock_timeout = '5s';

ALTER TABLE data_step_run DROP CONSTRAINT IF EXISTS ck_core_data_step_run_kind;
ALTER TABLE data_step_run ADD CONSTRAINT ck_core_data_step_run_kind CHECK (
    kind = ANY (ARRAY['copy', 'convert', 'map_values', 'set_default', 'retype', 'archive',
                      'orphan_scan', 'partition', 'split', 'extract_child',
                      'link_copy'])
);
