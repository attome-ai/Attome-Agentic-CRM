-- J2-T2: shared mailboxes routed into cases, leads and contacts.
-- inbound_mail_state is where each mailbox system's reading stopped;
-- inbound_mail_message keeps each Message-ID once per mailbox with where it
-- went (or why it was skipped), so a re-read never routes a message twice.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS inbound_mail_state (
    system_id  uuid        PRIMARY KEY,
    cursor     text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inbound_mail_message (
    system_id   uuid        NOT NULL,
    message_id  text        NOT NULL,
    outcome     text        NOT NULL,
    entity_name text,
    record_id   uuid,
    error       text,
    routed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (system_id, message_id)
);

CREATE INDEX IF NOT EXISTS inbound_mail_message_routed_idx
    ON inbound_mail_message (routed_at);

GRANT SELECT, INSERT, UPDATE ON inbound_mail_state, inbound_mail_message TO attome_runtime;
GRANT SELECT ON inbound_mail_state, inbound_mail_message TO attome_readonly;
