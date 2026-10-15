-- AB7-T8: deploy and restart history. One `start` row per boot (process
-- start to ready) and one `drain` row per shutdown (signal to exit), so an
-- operator sees when each node restarted, which version it ran, who started
-- it, how long it took and how many requests failed while it drained.
CREATE TABLE IF NOT EXISTS deploy_event (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    node text NOT NULL CHECK (char_length(node) BETWEEN 1 AND 300),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 100),
    kind text NOT NULL CHECK (kind IN ('start', 'drain', 'restart')),
    started_by text CHECK (char_length(started_by) <= 200),
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    failed_requests bigint CHECK (failed_requests >= 0)
);

CREATE INDEX IF NOT EXISTS deploy_event_started_at_idx ON deploy_event (started_at DESC);

GRANT SELECT, INSERT, UPDATE ON deploy_event TO attome_runtime;
GRANT SELECT ON deploy_event TO attome_readonly;
