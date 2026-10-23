-- L1-T3: the source_system_rank survivorship strategy. Its trust per source
-- system per attribute lives in the rule's new config column; existing rules
-- keep a NULL config and are read exactly as before.
SET LOCAL lock_timeout = '5s';

ALTER TABLE survivorship_rule ADD COLUMN IF NOT EXISTS config jsonb;

ALTER TABLE survivorship_rule DROP CONSTRAINT IF EXISTS survivorship_rule_strategy_chk;
ALTER TABLE survivorship_rule ADD CONSTRAINT survivorship_rule_strategy_chk
    CHECK (strategy IN ('most_recent', 'most_complete', 'source_priority', 'manual',
                        'source_system_rank'));
