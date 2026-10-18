-- Y2-T4: the orphan scan runs as a data step run of kind 'orphan_scan' on a
-- table over the size gate; 'partition' is admitted now for the partitioning
-- step that follows. One queued or running scan per entity.
ALTER TABLE data_step_run DROP CONSTRAINT IF EXISTS ck_core_data_step_run_kind;
ALTER TABLE data_step_run ADD CONSTRAINT ck_core_data_step_run_kind CHECK (
    kind = ANY (ARRAY['copy', 'convert', 'map_values', 'set_default', 'retype', 'archive',
                      'orphan_scan', 'partition'])
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_data_step_run_orphan_scan_live
    ON data_step_run (entity_logicalname)
    WHERE kind = 'orphan_scan' AND status IN ('queued', 'claimed', 'running');
