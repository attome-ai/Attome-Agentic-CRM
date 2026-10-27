-- A24-T4: the waves a migration project runs in. A wave reads what changed
-- at the source since the previous wave began (`since`; none for the
-- first, full load), brings the metadata in line and queues one import per
-- page of source records. `counts` holds what it did.
CREATE TABLE IF NOT EXISTS migration_wave (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES migration_project (id) ON DELETE CASCADE,
    system text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('full', 'catch_up', 'cut_over')),
    since timestamptz NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'loaded', 'failed')),
    counts jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz NULL,
    finished_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS migration_wave_project_idx ON migration_wave (project_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON migration_wave TO attome_runtime;
GRANT SELECT ON migration_wave TO attome_readonly;
