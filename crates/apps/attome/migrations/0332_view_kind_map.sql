-- B15-T2: the map view kind, which places each record at its geolocation
-- field. The kind CHECK gains `map`; the constraint is added NOT VALID and
-- validated after, and the lock is waited for at most 5 seconds, so a busy
-- view table fails the migration rather than holding up readers.
SET LOCAL lock_timeout = '5s';

ALTER TABLE view DROP CONSTRAINT IF EXISTS core_view_kind_range;
ALTER TABLE view ADD CONSTRAINT core_view_kind_range
    CHECK (kind IN ('list', 'kanban', 'calendar', 'timeline', 'chart', 'map')) NOT VALID;
ALTER TABLE view VALIDATE CONSTRAINT core_view_kind_range;
