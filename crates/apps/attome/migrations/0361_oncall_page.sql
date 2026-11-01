-- H7-T2: each page a major incident sends, and when the paged person
-- acknowledged it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS oncall_page (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    ticket_ref      uuid        NOT NULL,
    user_ref        uuid        NOT NULL,
    subject         text        NOT NULL,
    paged_at        timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz
);
CREATE INDEX IF NOT EXISTS oncall_page_user_idx ON oncall_page (user_ref, paged_at DESC);

GRANT SELECT, INSERT, UPDATE ON oncall_page TO attome_runtime;
GRANT SELECT ON oncall_page TO attome_readonly;
