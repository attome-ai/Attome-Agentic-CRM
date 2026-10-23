-- M13-T3: per-record ordering and automatic pause of a failing endpoint.
-- `ordered`: a delivery waits while an earlier one for the same record is
-- still pending, being delivered or failed (retrying). `paused_at` /
-- `paused_reason`: set when the delivery sweep turned the subscription off
-- because its endpoint kept failing; turning it back on clears them.
ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS ordered boolean NOT NULL DEFAULT false;
ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS paused_at timestamptz;
ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS paused_reason text;

-- The ordered-mode check: is an earlier delivery of this record still open?
CREATE INDEX IF NOT EXISTS event_delivery_open_per_record_idx
    ON event_delivery (subscription_ref, event_record_id, id)
    WHERE status IN ('pending', 'delivering', 'failed');
