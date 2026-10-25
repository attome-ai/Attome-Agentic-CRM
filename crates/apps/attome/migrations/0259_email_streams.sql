-- Z8-T3: transactional and bulk mail are separate streams. A suppression row
-- now names the stream it blocks: 'all' (a hard bounce, a complaint, an
-- administrator's entry: nothing is sent) or 'bulk' (an unsubscribe: bulk mail
-- stops, sign-in codes and other transactional mail still go out).
-- Existing rows are all 'all', which is what they meant before.

ALTER TABLE email_suppression
    ADD COLUMN IF NOT EXISTS stream TEXT NOT NULL DEFAULT 'all';

ALTER TABLE email_suppression DROP CONSTRAINT IF EXISTS email_suppression_stream_check;
ALTER TABLE email_suppression
    ADD CONSTRAINT email_suppression_stream_check CHECK (stream IN ('all', 'bulk'));

ALTER TABLE email_suppression DROP CONSTRAINT IF EXISTS email_suppression_reason_check;
ALTER TABLE email_suppression
    ADD CONSTRAINT email_suppression_reason_check
    CHECK (reason IN ('hard_bounce', 'complaint', 'admin_manual', 'unsubscribe'));

-- One live row per address and stream.
DROP INDEX IF EXISTS idx_email_suppression_email_active;
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_suppression_email_stream_active
    ON email_suppression (email, stream) WHERE is_deleted = FALSE;
