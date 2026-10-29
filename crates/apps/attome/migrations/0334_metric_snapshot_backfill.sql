-- P9-T10: a snapshot computed later for a past period by the metric backfill
-- job. Added on the partitioned parent; every partition inherits the column.
-- Rows written before this were computed on schedule or on demand.
ALTER TABLE metric_snapshot
    ADD COLUMN IF NOT EXISTS is_backfill boolean NOT NULL DEFAULT false;
