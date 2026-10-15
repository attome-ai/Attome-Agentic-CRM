-- L7-T1: a change-feed consumer that falls more than `max_lag_hours` behind
-- (the oldest event it has not read is older than that) is marked expired;
-- pruning then moves past it instead of keeping the whole feed for it.
-- Outside consumers (webhook subscriptions) get a week; the platform's own
-- consumers a month.
ALTER TABLE change_consumer_cursor ADD COLUMN IF NOT EXISTS max_lag_hours integer NOT NULL DEFAULT 168;
ALTER TABLE change_consumer_cursor ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE change_consumer_cursor ADD COLUMN IF NOT EXISTS expired_at timestamptz;
ALTER TABLE change_consumer_cursor DROP CONSTRAINT IF EXISTS change_consumer_cursor_lag_chk;
ALTER TABLE change_consumer_cursor ADD CONSTRAINT change_consumer_cursor_lag_chk CHECK (
    status IN ('active', 'expired') AND max_lag_hours > 0
);
UPDATE change_consumer_cursor
   SET max_lag_hours = 720
 WHERE max_lag_hours = 168
   AND consumer LIKE ANY (ARRAY['attome-workflow/%', 'attome-search/%', 'mdm/%', 'catalog/%',
                                'attome-service/%']);
