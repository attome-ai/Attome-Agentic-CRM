-- P9-T5: a metric with dimensions stores one snapshot row per member beside
-- its total. The total row has both dimension columns NULL; a member row
-- names the dimension attribute(s) and the member's value. The metric's
-- definition version is kept on every row.
SET LOCAL lock_timeout = '5s';

ALTER TABLE metric_snapshot ADD COLUMN IF NOT EXISTS dimension_attribute text;
ALTER TABLE metric_snapshot ADD COLUMN IF NOT EXISTS dimension_value text;
ALTER TABLE metric_snapshot ADD COLUMN IF NOT EXISTS definition_version integer;

CREATE INDEX IF NOT EXISTS metric_snapshot_member_idx
    ON metric_snapshot (metric_ref, period_start, dimension_attribute, dimension_value)
    WHERE dimension_attribute IS NOT NULL;
