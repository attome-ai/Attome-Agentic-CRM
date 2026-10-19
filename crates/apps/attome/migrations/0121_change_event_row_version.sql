-- A16-T2: the row version a generic update wrote, on its change event, so a
-- stale update sent with `If-Match-Merge: attributes` can tell exactly which
-- attributes each version it missed changed. Null for every other write.
-- Adding a nullable column changes no row; the partial index starts empty.
ALTER TABLE entity_change_event ADD COLUMN IF NOT EXISTS row_version bigint;

CREATE INDEX IF NOT EXISTS entity_change_event_record_version_idx
    ON entity_change_event (entity_logicalname, record_id, row_version)
    WHERE row_version IS NOT NULL;
