-- T5-T1: a sandbox copy asked for through POST /api/v1/admin/sandboxes.
-- The registered job `sandbox_copy` makes it (attome::scratch, the same
-- code as `attome scratch create`) and records how it went.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sandbox_request (
    id uuid PRIMARY KEY,
    database_name text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('full', 'metadata', 'sample')),
    sample_percent smallint CHECK (sample_percent IS NULL OR sample_percent BETWEEN 1 AND 99),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    detail text,
    requested_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS sandbox_request_live_name
    ON sandbox_request (database_name) WHERE status IN ('queued', 'running', 'done');

GRANT SELECT, INSERT, UPDATE ON sandbox_request TO attome_runtime;
