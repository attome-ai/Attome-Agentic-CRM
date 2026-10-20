-- E7-T5: a static list import from a CSV document — its progress, so the
-- job can be followed, and its finish time, which bounds its undo.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS marketing_list_import (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    list_id     uuid        NOT NULL,
    document_id uuid        NOT NULL,
    status      text        NOT NULL DEFAULT 'queued'
                CHECK (status = ANY (ARRAY['queued', 'running', 'done', 'failed', 'undone'])),
    rows_read   integer     NOT NULL DEFAULT 0,
    added       integer     NOT NULL DEFAULT 0,
    skipped     integer     NOT NULL DEFAULT 0,
    error       text,
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS marketing_list_import_list_idx
    ON marketing_list_import (list_id, created_at);

GRANT SELECT, INSERT, UPDATE ON marketing_list_import TO attome_runtime;
GRANT SELECT ON marketing_list_import TO attome_readonly;
