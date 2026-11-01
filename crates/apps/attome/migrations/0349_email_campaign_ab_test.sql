-- E4-T1: an email campaign can test variants. Each variant keeps its own
-- subject and rendered bodies, a tracked copy of its HTML, and the fixed
-- links of that copy, which the click route redirects to by position. A
-- test sends each variant, tracked, to its share of the recipients and
-- holds the rest ('held'); once the window has passed the sweep picks the
-- winner by opens or clicks and releases the held recipients to it,
-- untracked. Opens and clicks are kept per tracked recipient.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS email_campaign_variant (
    send_id uuid NOT NULL REFERENCES email_campaign_send (id),
    name text NOT NULL,
    subject text NOT NULL,
    html_body text NOT NULL,
    text_body text NOT NULL,
    tracked_html text NOT NULL,
    links jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (send_id, name)
);

ALTER TABLE email_campaign_send
    ADD COLUMN IF NOT EXISTS ab_metric text CHECK (ab_metric IN ('opens', 'clicks')),
    ADD COLUMN IF NOT EXISTS ab_window_minutes integer,
    ADD COLUMN IF NOT EXISTS ab_fallback text CHECK (ab_fallback IN ('leader', 'stop')),
    ADD COLUMN IF NOT EXISTS ab_winner text,
    ADD COLUMN IF NOT EXISTS ab_decided_at timestamptz,
    ADD COLUMN IF NOT EXISTS ab_decision jsonb;

ALTER TABLE email_campaign_recipient
    ADD COLUMN IF NOT EXISTS variant text,
    ADD COLUMN IF NOT EXISTS tracked boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS opened_at timestamptz,
    ADD COLUMN IF NOT EXISTS clicked_at timestamptz;

ALTER TABLE email_campaign_recipient
    DROP CONSTRAINT IF EXISTS email_campaign_recipient_status_check;
ALTER TABLE email_campaign_recipient
    ADD CONSTRAINT email_campaign_recipient_status_check
    CHECK (status IN ('pending', 'sent', 'skipped', 'capped', 'failed', 'held'));

CREATE INDEX IF NOT EXISTS email_campaign_recipient_held_idx
    ON email_campaign_recipient (send_id) WHERE status = 'held';

GRANT SELECT, INSERT ON email_campaign_variant TO attome_runtime;
GRANT SELECT ON email_campaign_variant TO attome_readonly;
