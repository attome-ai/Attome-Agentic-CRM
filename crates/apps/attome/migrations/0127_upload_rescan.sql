-- K2-T2: files promoted in the last 30 days are scanned again weekly, so a
-- virus signature published after the upload still catches it. A session
-- remembers when its file was last rescanned.
ALTER TABLE upload_session ADD COLUMN IF NOT EXISTS rescanned_at timestamptz;

CREATE INDEX IF NOT EXISTS upload_session_rescan_idx ON upload_session (updated_at)
    WHERE status = 'clean' AND is_deleted = false;
