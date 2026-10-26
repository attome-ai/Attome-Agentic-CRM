-- M8-T2: a state model may govern one record type, lock states, and name
-- the status reasons each state allows. The one-active-model-per-entity
-- index becomes one active model per (entity, record type): NULL is the
-- entity's model for every record without a type of its own.
SET LOCAL lock_timeout = '5s';

-- Nullable columns with no default are metadata-only (no table rewrite).
ALTER TABLE state_model ADD COLUMN IF NOT EXISTS record_type text;
ALTER TABLE state_model ADD COLUMN IF NOT EXISTS locked_states jsonb;
ALTER TABLE state_model ADD COLUMN IF NOT EXISTS reason_field text;
ALTER TABLE state_model ADD COLUMN IF NOT EXISTS reasons jsonb;

-- state_model is a small admin-authored table, so a plain index build is
-- brief; the new index exists before the old one goes, so uniqueness is
-- never unguarded.
CREATE UNIQUE INDEX IF NOT EXISTS state_model_entity_type_active_idx
    ON state_model (entity_logicalname, COALESCE(record_type, ''))
    WHERE is_deleted = false AND is_active = true;
DROP INDEX IF EXISTS core_state_model_entity_active_idx;
