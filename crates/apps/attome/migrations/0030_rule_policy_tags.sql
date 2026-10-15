-- B4-T3: business rules tag records. `add_tag` and `remove_tag` name a
-- shared tag in `value` (a string) and apply to the record written while the
-- rule's condition holds.
ALTER TABLE rule_policy DROP CONSTRAINT IF EXISTS rule_policy_policy_type_check;
ALTER TABLE rule_policy ADD CONSTRAINT rule_policy_policy_type_check CHECK (
    policy_type = ANY (ARRAY['hidden', 'disabled', 'error', 'set_value', 'required',
                             'allowed_values', 'add_tag', 'remove_tag'])
);
ALTER TABLE rule_policy DROP CONSTRAINT IF EXISTS ck_core_rule_policy_shape;
ALTER TABLE rule_policy ADD CONSTRAINT ck_core_rule_policy_shape CHECK (
    (policy_type IN ('hidden', 'disabled') AND field_logicalname IS NOT NULL AND message IS NULL
        AND severity IS NULL AND value IS NULL AND expression IS NULL AND set_mode IS NULL)
    OR (policy_type = 'error' AND severity IS NOT NULL AND value IS NULL AND expression IS NULL
        AND set_mode IS NULL)
    OR (policy_type = 'set_value' AND field_logicalname IS NOT NULL AND set_mode IS NOT NULL
        AND num_nonnulls(value, expression) = 1 AND message IS NULL AND severity IS NULL)
    OR (policy_type = 'required' AND field_logicalname IS NOT NULL AND severity IS NULL
        AND value IS NULL AND expression IS NULL AND set_mode IS NULL)
    OR (policy_type = 'allowed_values' AND field_logicalname IS NOT NULL
        AND jsonb_typeof(value) = 'array' AND severity IS NULL AND expression IS NULL
        AND set_mode IS NULL)
    OR (policy_type IN ('add_tag', 'remove_tag') AND field_logicalname IS NULL
        AND jsonb_typeof(value) = 'string' AND message IS NULL AND severity IS NULL
        AND expression IS NULL AND set_mode IS NULL)
);
