-- W1-T8: contract negotiation rounds. A review link is one round of one
-- contract, emailed to the counterparty; opening the next round, or the
-- counterparty sending a version, closes it. Entries are what came back
-- through the link: comments, and uploads whose scan the contract_review
-- job waits for before setting the file on the version and comparing it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS contract_review_link (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    contract_id uuid        NOT NULL,
    round       integer     NOT NULL,
    email       text        NOT NULL,
    name        text,
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    closed_at   timestamptz,
    UNIQUE (contract_id, round)
);

CREATE TABLE IF NOT EXISTS contract_review_entry (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    link_id       uuid        NOT NULL REFERENCES contract_review_link (id) ON DELETE CASCADE,
    kind          text        NOT NULL CHECK (kind IN ('comment', 'upload')),
    body          text,
    file_name     text,
    session_id    uuid,
    version_id    uuid,
    comparison_id uuid,
    created_at    timestamptz NOT NULL DEFAULT now(),
    processed_at  timestamptz
);
CREATE INDEX IF NOT EXISTS contract_review_entry_link_idx
    ON contract_review_entry (link_id, created_at);
CREATE INDEX IF NOT EXISTS contract_review_entry_pending_idx
    ON contract_review_entry (created_at) WHERE kind = 'upload' AND processed_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON contract_review_link, contract_review_entry TO attome_runtime;
GRANT SELECT ON contract_review_link, contract_review_entry TO attome_readonly;
