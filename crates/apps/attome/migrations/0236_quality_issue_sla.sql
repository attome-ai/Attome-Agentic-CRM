-- L2-T4: the days a data quality issue of an entity is due in (default 7
-- when unset).
SET LOCAL lock_timeout = '5s';

ALTER TABLE quality_target ADD COLUMN IF NOT EXISTS issue_sla_days integer
    CHECK (issue_sla_days IS NULL OR issue_sla_days > 0);

CREATE INDEX IF NOT EXISTS quality_issue_owner_idx ON quality_issue (owner_id)
    WHERE owner_id IS NOT NULL;
