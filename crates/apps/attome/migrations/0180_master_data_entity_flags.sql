-- L1-T1: master-data settings on entity metadata. An entity can be marked
-- as master data with a hub style (registry, consolidation, coexistence);
-- a master entity needs a data domain (domain_ref), which the
-- set_entity_master_data operation checks. Both travel in changesets.
SET LOCAL lock_timeout = '5s';

ALTER TABLE entity_info
    ADD COLUMN IF NOT EXISTS is_master boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS hub_style text;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'entity_info_hub_style_check') THEN
        ALTER TABLE entity_info ADD CONSTRAINT entity_info_hub_style_check
            CHECK (hub_style IS NULL OR hub_style IN ('registry', 'consolidation', 'coexistence'));
    END IF;
END
$$;
