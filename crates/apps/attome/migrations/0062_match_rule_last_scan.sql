-- A15-T6: when a match rule's full scan last finished, so a scheduled scan
-- (scan_schedule hourly, daily or weekly) knows when it is due.
SET LOCAL lock_timeout = '5s';

ALTER TABLE match_rule ADD COLUMN IF NOT EXISTS last_scan_at timestamptz;
