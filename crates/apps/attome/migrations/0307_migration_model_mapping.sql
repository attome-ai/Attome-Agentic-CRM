-- A24-T3: one migration project's model mapping (source entities and
-- fields to this deployment's entities and attributes), kept as a document
-- the person edits as a table. Its version guards concurrent edits.
CREATE TABLE IF NOT EXISTS migration_model_mapping (
    project_id uuid PRIMARY KEY REFERENCES migration_project (id) ON DELETE CASCADE,
    source_model jsonb NOT NULL,
    mapping jsonb NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    updated_by uuid NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON migration_model_mapping TO attome_runtime;
GRANT SELECT ON migration_model_mapping TO attome_readonly;
