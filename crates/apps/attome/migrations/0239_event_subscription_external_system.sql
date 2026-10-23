-- L1-T7: the system a webhook subscriber is, as master-data contributions
-- name it (`source_system`), so a golden-record change is sent with the
-- subscriber's own external id for the record.
SET LOCAL lock_timeout = '5s';

ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS external_system text;
