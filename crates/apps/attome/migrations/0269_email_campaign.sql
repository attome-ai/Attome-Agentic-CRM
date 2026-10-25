-- E3-T1: an email campaign to a marketing list. The send keeps a snapshot
-- of the subject and rendered bodies it went out with; each recipient is
-- one row the bulk sweep works through, with the token its one-click
-- unsubscribe link carries.
CREATE TABLE IF NOT EXISTS email_campaign_send (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    list_id uuid NOT NULL,
    subject text NOT NULL,
    html_body text NOT NULL,
    text_body text NOT NULL,
    purpose_key text NOT NULL,
    locale text NOT NULL DEFAULT 'en',
    status text NOT NULL DEFAULT 'sending' CHECK (status IN ('sending', 'done')),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS email_campaign_recipient (
    send_id uuid NOT NULL REFERENCES email_campaign_send (id),
    subject_entity text NOT NULL,
    subject_id uuid NOT NULL,
    email text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sent', 'skipped', 'capped', 'failed')),
    unsubscribe_token text NOT NULL UNIQUE,
    attempted_at timestamptz,
    PRIMARY KEY (send_id, subject_id)
);

CREATE INDEX IF NOT EXISTS email_campaign_recipient_pending_idx
    ON email_campaign_recipient (send_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS email_campaign_recipient_sent_idx
    ON email_campaign_recipient (subject_entity, subject_id, attempted_at)
    WHERE status = 'sent';

GRANT SELECT, INSERT, UPDATE ON email_campaign_send TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON email_campaign_recipient TO attome_runtime;
GRANT SELECT ON email_campaign_send TO attome_readonly;
GRANT SELECT ON email_campaign_recipient TO attome_readonly;
