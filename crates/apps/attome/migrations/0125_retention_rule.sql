-- R3-T1: retention rules per entity and category. A rule names the records
-- it covers (an entity and an optional filter condition), the date attribute
-- their retention period starts from (created, closed, contract end...), the
-- period, and what to do once it has passed: purge, archive or review. The
-- daily proposal sweep turns each record past its rule's period into a
-- proposal in audit_retention_action (approved by a person before anything
-- happens); records under a legal hold are skipped.
CREATE TABLE IF NOT EXISTS retention_rule (
    id                 uuid        PRIMARY KEY DEFAULT uuidv7(),
    name               text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    entity_logicalname text        NOT NULL,
    category           text        CHECK (category IS NULL OR char_length(category) <= 100),
    condition          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    start_attribute    text        NOT NULL DEFAULT 'created_at',
    period_days        integer     NOT NULL CHECK (period_days BETWEEN 1 AND 36500),
    action             text        NOT NULL CHECK (action = ANY (ARRAY['purge', 'archive', 'review'])),
    is_active          boolean     NOT NULL DEFAULT true,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    row_version        bigint      NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS retention_rule_entity_idx ON retention_rule (entity_logicalname)
    WHERE is_active;

-- A rule's proposals name the rule that made them; the three rule actions
-- join the existing proposal kinds.
ALTER TABLE audit_retention_action ADD COLUMN IF NOT EXISTS rule_ref uuid;
ALTER TABLE audit_retention_action DROP CONSTRAINT IF EXISTS audit_retention_action_action_type_check;
ALTER TABLE audit_retention_action ADD CONSTRAINT audit_retention_action_action_type_check CHECK (
    action_type = ANY (ARRAY['partition_archive', 'entity_purge', 'archive',
                             'rule_purge', 'rule_archive', 'rule_review'])
);

GRANT SELECT, INSERT, UPDATE, DELETE ON retention_rule TO attome_runtime;
GRANT SELECT ON retention_rule TO attome_readonly;
