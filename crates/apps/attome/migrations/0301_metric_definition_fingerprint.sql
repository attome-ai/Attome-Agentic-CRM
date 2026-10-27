-- P9-T9: the fingerprint of the metric definition fields a snapshot was
-- computed with. A snapshot whose fingerprint differs from the metric's last
-- one starts a new definition_version (0086). Added on the partitioned parent;
-- every partition inherits the column. Rows written before this have none and
-- keep their version.
ALTER TABLE metric_snapshot
    ADD COLUMN IF NOT EXISTS definition_fingerprint text;

CREATE INDEX IF NOT EXISTS idx_metric_snapshot_metric_latest
    ON metric_snapshot (metric_ref, computed_at DESC)
    WHERE dimension_attribute IS NULL;
