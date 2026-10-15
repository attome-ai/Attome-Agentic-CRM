-- AA10-T1: heavy operations (an update or delete over a filter that may
-- match millions of rows) run in chunks. One row per operation with its
-- progress counts, and one row per chunk with the last id it reached (the
-- checkpoint a restart resumes from) and the values it replaced (what undo
-- writes back).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS heavy_operation (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    kind text NOT NULL,
    entity_logicalname text NOT NULL,
    filter jsonb NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('estimating', 'queued', 'running', 'paused', 'cancelled',
        'failed', 'done', 'undone')),
    estimated_rows bigint,
    rows_done bigint NOT NULL DEFAULT 0,
    rows_skipped_permission bigint NOT NULL DEFAULT 0,
    rows_conflict bigint NOT NULL DEFAULT 0,
    started_by uuid NOT NULL,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS heavy_operation_status_idx ON heavy_operation (status, created_at);

CREATE TABLE IF NOT EXISTS heavy_operation_chunk (
    operation_id uuid NOT NULL REFERENCES heavy_operation (id),
    chunk_no integer NOT NULL,
    last_id uuid,
    status text NOT NULL,
    before_values jsonb,
    PRIMARY KEY (operation_id, chunk_no)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON heavy_operation, heavy_operation_chunk TO attome_runtime;
GRANT SELECT ON heavy_operation, heavy_operation_chunk TO attome_readonly;
