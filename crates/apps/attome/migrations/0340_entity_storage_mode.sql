-- A1-T6: an entity's storage. `high_volume` tables are partitioned by month
-- on created_at (attome_metadata::provision::table), with a BRIN index on
-- it; reads must name a window on created_at. Set when the entity is
-- created and never changed in place.
SET LOCAL lock_timeout = '5s';

ALTER TABLE entity_info ADD COLUMN IF NOT EXISTS storage_mode varchar(20) NOT NULL DEFAULT 'standard'
    CHECK (storage_mode IN ('standard', 'high_volume'));
