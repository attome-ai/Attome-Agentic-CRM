-- E27-T1: marketing consent per person (or whole account), purpose and
-- channel. consent_event is the insert-only record of every grant and
-- withdrawal with its proof; consent_current holds the latest state per
-- subject, purpose and channel and is written in the same transaction as
-- the event that changed it. A channel of 'any' covers every channel.
CREATE TABLE IF NOT EXISTS consent_event (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    subject_entity text NOT NULL,
    subject_id uuid NOT NULL,
    purpose_key text NOT NULL,
    channel text NOT NULL
        CHECK (channel IN ('any', 'email', 'sms', 'whatsapp', 'phone', 'ads')),
    action text NOT NULL CHECK (action IN ('grant', 'withdraw')),
    source text NOT NULL,
    proof jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    recorded_by uuid
);

CREATE INDEX IF NOT EXISTS consent_event_subject_idx
    ON consent_event (subject_entity, subject_id, occurred_at);

CREATE TABLE IF NOT EXISTS consent_current (
    subject_entity text NOT NULL,
    subject_id uuid NOT NULL,
    purpose_key text NOT NULL,
    channel text NOT NULL,
    status text NOT NULL CHECK (status IN ('granted', 'withdrawn')),
    event_id uuid NOT NULL REFERENCES consent_event (id),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (subject_entity, subject_id, purpose_key, channel)
);

-- The log is append-only for the application.
GRANT SELECT, INSERT ON consent_event TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON consent_current TO attome_runtime;
GRANT SELECT ON consent_event, consent_current TO attome_readonly;
