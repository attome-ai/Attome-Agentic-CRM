-- T5-T2 (V2-D274, V2-D1722): Develop workspaces inside the deployment. Each
-- workspace is its own schema (`schema_name`) holding copies of the metadata
-- tables and the entity tables; this row is its registry entry. Users,
-- sessions, audit and jobs stay shared with live.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS develop_workspace (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    purpose text CHECK (purpose IS NULL OR char_length(purpose) <= 1000),
    schema_name text NOT NULL UNIQUE,
    owner_ref uuid NOT NULL,
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'publishing', 'published', 'discarded')),
    changeset_ref uuid,
    metadata_tables integer NOT NULL DEFAULT 0,
    entity_tables integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS develop_workspace_by_status
    ON develop_workspace (status, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON develop_workspace TO attome_runtime;
