-- E16-T1: SMS campaigns. A send is one message to a marketing list's
-- consenting members; its recipients are fixed when it starts, and the
-- `sms_campaign` job sends them in batches, holding each until its quiet
-- hours end.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sms_campaign_send (
    id                uuid        PRIMARY KEY DEFAULT uuidv7(),
    list_id           uuid        NOT NULL,
    body              text        NOT NULL,
    purpose_key       text        NOT NULL,
    segments_each     integer     NOT NULL,
    estimated_cost    numeric,
    status            text        NOT NULL DEFAULT 'sending'
                      CHECK (status = ANY (ARRAY['sending', 'done', 'cancelled'])),
    created_by        uuid        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);

CREATE TABLE IF NOT EXISTS sms_campaign_recipient (
    send_id        uuid        NOT NULL REFERENCES sms_campaign_send (id) ON DELETE CASCADE,
    subject_entity text        NOT NULL,
    subject_id     uuid        NOT NULL,
    phone          text        NOT NULL,
    status         text        NOT NULL DEFAULT 'pending'
                   CHECK (status = ANY (ARRAY['pending', 'sent', 'skipped', 'failed'])),
    delivery_id    uuid,
    attempted_at   timestamptz,
    PRIMARY KEY (send_id, subject_id)
);

CREATE INDEX IF NOT EXISTS sms_campaign_recipient_pending_idx
    ON sms_campaign_recipient (send_id) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON sms_campaign_send, sms_campaign_recipient TO attome_runtime;
GRANT SELECT ON sms_campaign_send, sms_campaign_recipient TO attome_readonly;
