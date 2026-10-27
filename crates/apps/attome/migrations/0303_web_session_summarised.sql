-- E14-T8: when a closed, identified web session became a visit summary on
-- the person's timeline, so each session is summarised once.
ALTER TABLE marketing_web_session
    ADD COLUMN IF NOT EXISTS summarised_at timestamptz;

CREATE INDEX IF NOT EXISTS marketing_web_session_unsummarised_idx
    ON marketing_web_session (last_seen_at)
    WHERE summarised_at IS NULL AND (contact_ref IS NOT NULL OR lead_ref IS NOT NULL);
