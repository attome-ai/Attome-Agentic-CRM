-- K6-T10: a crawl target's run history. A run opens when the crawl starts
-- and closes with how it ended, the pages it recorded and what the sync
-- after it did to the source's knowledge items.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS webcrawl_run (
    id             uuid        PRIMARY KEY DEFAULT uuidv7(),
    target_id      uuid        NOT NULL REFERENCES webcrawl_target (id) ON DELETE CASCADE,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    status         text        NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running', 'completed', 'failed')),
    pages_found    integer     NOT NULL DEFAULT 0,
    items_imported integer     NOT NULL DEFAULT 0,
    items_updated  integer     NOT NULL DEFAULT 0,
    items_flagged  integer     NOT NULL DEFAULT 0,
    error          text
);
CREATE INDEX IF NOT EXISTS webcrawl_run_target_idx ON webcrawl_run (target_id, started_at DESC);

GRANT SELECT, INSERT, UPDATE ON webcrawl_run TO attome_runtime;
GRANT SELECT ON webcrawl_run TO attome_readonly;
