-- A24-T4: the source files a migration copied onto a migrated record's
-- multi-file `attachments` field. A file is copied once per project
-- (`source_file_id`), whichever wave sees it first: `scanning` while its
-- upload session awaits the scan, `attached` once its key is on the record,
-- `failed` with the reason. A row whose `source_file_id` is `*<wave id>`
-- marks a record that wave already looked at.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS migration_file_copy (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES migration_project (id) ON DELETE CASCADE,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    source_file_id text NOT NULL,
    session_id uuid,
    status text NOT NULL CHECK (status IN ('scanning', 'attached', 'failed', 'checked')),
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, entity, record_id, source_file_id)
);

CREATE INDEX IF NOT EXISTS migration_file_copy_scanning_idx
    ON migration_file_copy (project_id) WHERE status = 'scanning';

GRANT SELECT, INSERT, UPDATE ON migration_file_copy TO attome_runtime;
GRANT SELECT ON migration_file_copy TO attome_readonly;
