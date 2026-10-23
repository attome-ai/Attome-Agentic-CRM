-- L6-T5: the drift a profile found against the entity's previous one, and
-- the scheduled profile slots already started (one per entity and slot).
ALTER TABLE data_profile ADD COLUMN IF NOT EXISTS drift jsonb;

CREATE TABLE IF NOT EXISTS data_profile_schedule_slot (
    entity_logicalname text NOT NULL,
    slot_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_logicalname, slot_at)
);

GRANT SELECT, INSERT ON data_profile_schedule_slot TO attome_runtime;
