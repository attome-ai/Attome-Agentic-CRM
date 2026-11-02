-- O1-T3: a model from a definition (O1-T1). The definition is stored with
-- the model; its target is `def:<attribute>`.
SET LOCAL lock_timeout = '5s';

ALTER TABLE prediction_model ADD COLUMN IF NOT EXISTS definition jsonb;

ALTER TABLE prediction_model DROP CONSTRAINT IF EXISTS prediction_model_target_chk;
ALTER TABLE prediction_model ADD CONSTRAINT prediction_model_target_chk CHECK (
    target::text = ANY (ARRAY['sla_breach', 'capacity_shortfall', 'anomaly'])
    OR target::text LIKE 'custom_metric:%'
    OR (target::text LIKE 'def:%' AND definition IS NOT NULL)
);
