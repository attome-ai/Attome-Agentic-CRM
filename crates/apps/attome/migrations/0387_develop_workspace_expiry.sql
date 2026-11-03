-- T5-T6: a Develop workspace's idle expiry. The owner is warned once before
-- an idle workspace is discarded; using it again clears the warning.
SET LOCAL lock_timeout = '5s';

ALTER TABLE develop_workspace ADD COLUMN IF NOT EXISTS expiry_warned_at timestamptz;
