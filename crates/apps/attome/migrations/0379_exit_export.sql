-- Y5-T5 (V2-D1628 (4)): the clean-exit export and, after two administrators
-- approve, the deletion of everything else. This table is kept by the
-- deletion: it holds the signed deletion certificate.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS exit_export (
    id uuid PRIMARY KEY,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'done', 'failed', 'deleting', 'deleted')),
    requested_by uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    entities_total integer NOT NULL DEFAULT 0,
    entities_done integer NOT NULL DEFAULT 0,
    files_done integer NOT NULL DEFAULT 0,
    object_key text,
    sha256 text,
    bytes bigint,
    error text,
    approval_request_id uuid,
    deleted_at timestamptz,
    certificate jsonb,
    row_version bigint NOT NULL DEFAULT 0
);

GRANT SELECT, INSERT, UPDATE ON exit_export TO attome_runtime;
