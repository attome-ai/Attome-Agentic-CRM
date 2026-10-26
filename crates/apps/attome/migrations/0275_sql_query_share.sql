-- A14-T2: a stored query shared with a role or a team, to read (run it by id
-- through query/run) or to edit (also change its QuerySpec and parameters).
-- principal_type 0 = role, 1 = team (the record_share convention puts users
-- at 0; a query is never shared with one person). The share is deployment
-- state: it names this deployment's roles and teams and never travels in a
-- changeset.
CREATE TABLE IF NOT EXISTS sql_query_share (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    query_id uuid NOT NULL REFERENCES sql_query (id) ON DELETE CASCADE,
    principal_type smallint NOT NULL,
    principal_id uuid NOT NULL,
    access text NOT NULL,
    granted_by uuid NULL,
    granted_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT sql_query_share_principal_type_range CHECK (principal_type IN (0, 1)),
    CONSTRAINT sql_query_share_access_check CHECK (access IN ('read', 'edit')),
    CONSTRAINT uq_sql_query_share UNIQUE (query_id, principal_type, principal_id)
);

CREATE INDEX IF NOT EXISTS sql_query_share_principal_idx
    ON sql_query_share (principal_id, query_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON sql_query_share TO attome_runtime;
GRANT SELECT ON sql_query_share TO attome_readonly;
