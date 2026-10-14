-- The generalised reference graph (roadmap Y1-T4): how a source uses its
-- target. Existing rows (an entity or attribute read by a form, rule or
-- query) are reads. A metadata-model object target is stored as
-- `to_entity = '<kind>:<object id>'` with an empty `to_attribute`, so the
-- existing unique (from_kind, from_ref, to_entity, to_attribute) index still
-- holds one row per source and target.

ALTER TABLE metadata_reference
    ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'reads';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'metadata_reference_mode_check'
    ) THEN
        ALTER TABLE metadata_reference
            ADD CONSTRAINT metadata_reference_mode_check
            CHECK (mode IN ('reads', 'writes', 'triggers'));
    END IF;
END
$$;
