-- D15-T2: emails captured from people's own mailboxes. A captured email is
-- one communication on its first matching record; communication_link places
-- it on every other matching contact, lead and open opportunity, and the
-- record timeline reads both. mail_capture_message keeps each Message-ID
-- once, whoever's mailbox it was read from; mail_capture_state is where each
-- connection's reading stopped.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS communication_link (
    communication_id uuid NOT NULL,
    entity_name text NOT NULL,
    record_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (communication_id, entity_name, record_id)
);
CREATE INDEX IF NOT EXISTS communication_link_record_idx
    ON communication_link (entity_name, record_id);

CREATE TABLE IF NOT EXISTS mail_capture_message (
    message_id text PRIMARY KEY,
    communication_id uuid NOT NULL,
    user_id uuid REFERENCES user_account (id) ON DELETE SET NULL,
    captured_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mail_capture_state (
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    cursor text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, provider)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON communication_link, mail_capture_message, mail_capture_state
    TO attome_runtime;
GRANT SELECT ON communication_link, mail_capture_message, mail_capture_state TO attome_readonly;
