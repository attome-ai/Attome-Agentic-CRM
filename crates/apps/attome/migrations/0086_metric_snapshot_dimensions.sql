-- P9-T2: a metric snapshot per dimension member, the definition version it
-- was computed under, and whether it came from a backfill. Added on the
-- partitioned parent; every partition inherits the columns.
ALTER TABLE metric_snapshot
    ADD COLUMN IF NOT EXISTS dimension_attribute text,
    ADD COLUMN IF NOT EXISTS dimension_value text,
    ADD COLUMN IF NOT EXISTS definition_version integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS is_backfill boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_metric_snapshot_member
    ON metric_snapshot (metric_ref, period_start, dimension_attribute, dimension_value);
