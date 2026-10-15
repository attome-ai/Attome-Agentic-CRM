-- A23-T1: file imports as a job. The uploaded file is kept in storage (the
-- durable copy); its rows are staged, validated, approved when the policy
-- asks, applied in chunks from a cursor, and every written row is recorded so
-- the import can be undone. Re-uploading the same file to the same entity
-- finds the existing job instead of starting a duplicate.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS import_job (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    storage_key text NOT NULL,
    file_name text NOT NULL,
    file_sha256 text NOT NULL,
    encoding text,
    sheet text,
    mapping_ref uuid,
    mapping jsonb NOT NULL,
    match_mode text NOT NULL CHECK (match_mode IN ('create', 'update', 'upsert')),
    match_columns text[] NOT NULL DEFAULT '{}',
    all_or_nothing boolean NOT NULL DEFAULT false,
    triggers_on boolean NOT NULL DEFAULT false,
    status text NOT NULL CHECK (status IN ('uploaded', 'staged', 'validated', 'awaiting_approval',
        'applying', 'applied', 'failed', 'undoing', 'undone', 'cancelled')),
    counts jsonb NOT NULL DEFAULT '{}',
    cursor_row integer NOT NULL DEFAULT 0,
    approval_request_id uuid,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS import_job_file_uq ON import_job (entity_logicalname, file_sha256)
    WHERE status NOT IN ('failed', 'cancelled', 'undone');
CREATE INDEX IF NOT EXISTS import_job_creator_idx ON import_job (created_by, created_at DESC);

-- Unlogged on purpose: the source file in storage is the durable copy, and
-- staging is rebuilt from it after a crash.
CREATE UNLOGGED TABLE IF NOT EXISTS import_stage (
    job_id uuid NOT NULL,
    row_no integer NOT NULL,
    raw jsonb NOT NULL,
    mapped jsonb,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'valid', 'invalid', 'applied', 'skipped')),
    action text,
    record_id uuid,
    record_row_version bigint,
    error jsonb,
    PRIMARY KEY (job_id, row_no)
);

-- The durable record of what an import wrote, used by undo.
CREATE TABLE IF NOT EXISTS import_row (
    job_id uuid NOT NULL REFERENCES import_job (id),
    row_no integer NOT NULL,
    action text NOT NULL CHECK (action IN ('created', 'updated')),
    record_id uuid NOT NULL,
    before jsonb,
    after_row_version bigint NOT NULL,
    PRIMARY KEY (job_id, row_no)
);

CREATE TABLE IF NOT EXISTS import_policy (
    entity_logicalname text PRIMARY KEY,
    max_rows integer CHECK (max_rows IS NULL OR max_rows > 0),
    approval_over_rows integer CHECK (approval_over_rows IS NULL OR approval_over_rows > 0),
    allowed_roles text[] NOT NULL DEFAULT '{}',
    quiet_hours jsonb,
    sensitive_needs_approval boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 1
);

GRANT SELECT, INSERT, UPDATE, DELETE ON import_job, import_stage, import_row, import_policy
    TO attome_runtime;
GRANT SELECT ON import_job, import_stage, import_row, import_policy TO attome_readonly;
