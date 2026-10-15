-- A3-T4: a refusing check (error, required, allowed_values) is rolled out in
-- stages. `report` logs a failure, `warn` saves with a warning, `enforce`
-- refuses; `enforce_from` is the first day an enforced check refuses, and it
-- warns before then.
ALTER TABLE rule_policy ADD COLUMN IF NOT EXISTS stage text;
ALTER TABLE rule_policy ADD COLUMN IF NOT EXISTS enforce_from date;
ALTER TABLE rule_policy DROP CONSTRAINT IF EXISTS rule_policy_stage_check;
ALTER TABLE rule_policy ADD CONSTRAINT rule_policy_stage_check CHECK (
    (stage IS NULL AND enforce_from IS NULL)
    OR (policy_type IN ('error', 'required', 'allowed_values')
        AND stage IN ('report', 'warn', 'enforce')
        AND (enforce_from IS NULL OR stage = 'enforce'))
);
