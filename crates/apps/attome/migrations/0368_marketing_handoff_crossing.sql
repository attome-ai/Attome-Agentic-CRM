-- E9-T5: a nurtured person is handed to sales once each time their score
-- rises to the programme's hand-off score. The state remembers whether the
-- score is at or above it, so a crossing is the move from below to at or
-- above, and a score that stays high does not hand them off again.
SET LOCAL lock_timeout = '5s';

ALTER TABLE marketing_nurture_state
    ADD COLUMN IF NOT EXISTS above_threshold boolean NOT NULL DEFAULT false;
