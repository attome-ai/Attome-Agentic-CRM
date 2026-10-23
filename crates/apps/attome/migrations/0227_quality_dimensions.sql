-- L2-T2: the six quality dimensions and the weighted overall score are
-- daily scores; an entity's records count as timely when changed within
-- its timeliness_days.
SET LOCAL lock_timeout = '5s';

ALTER TABLE quality_score DROP CONSTRAINT IF EXISTS quality_score_dimension_check;
ALTER TABLE quality_score ADD CONSTRAINT quality_score_dimension_check
    CHECK (dimension IN ('completeness', 'uniqueness', 'validity', 'consistency',
                         'timeliness', 'accuracy', 'overall'));

ALTER TABLE quality_target ADD COLUMN IF NOT EXISTS timeliness_days integer
    CHECK (timeliness_days IS NULL OR timeliness_days > 0);
