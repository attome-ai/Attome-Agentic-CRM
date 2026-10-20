-- P10-T1: the lineage graph gains non-entity targets. A reference now names
-- what it points at: an entity (today's rows, to_kind = 'entity') or a
-- metric (to_kind = 'metric', to_ref = the metric's id; to_entity then holds
-- 'metric:<id>' so the existing unique key and every entity-name lookup stay
-- as they are). A metric records what it reads and a dashboard widget the
-- metrics it shows, so a metric's downstream consumers are one lookup.
SET LOCAL lock_timeout = '5s';

ALTER TABLE metadata_reference
    ADD COLUMN IF NOT EXISTS to_kind text NOT NULL DEFAULT 'entity',
    ADD COLUMN IF NOT EXISTS to_ref uuid;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'metadata_reference_to_kind_check') THEN
        ALTER TABLE metadata_reference ADD CONSTRAINT metadata_reference_to_kind_check
            CHECK (to_kind IN ('entity', 'metric'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS metadata_reference_object_target_idx
    ON metadata_reference (to_kind, to_ref) WHERE to_ref IS NOT NULL;
