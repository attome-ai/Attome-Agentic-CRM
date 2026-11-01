-- Y12-T9: columns a field deletion or a large type change retired (renamed,
-- values intact) and when the contraction job dropped them. A column goes
-- once the period has passed and every node has switched past the
-- metadata version recorded here.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS schema_retired_column (
    id uuid PRIMARY KEY,
    table_name text NOT NULL CHECK (char_length(table_name) BETWEEN 1 AND 63),
    column_name text NOT NULL CHECK (char_length(column_name) BETWEEN 1 AND 63),
    retired_name text NOT NULL CHECK (char_length(retired_name) BETWEEN 1 AND 63),
    metadata_version bigint,
    retired_at timestamptz NOT NULL DEFAULT now(),
    dropped_at timestamptz
);

CREATE INDEX IF NOT EXISTS schema_retired_column_pending
    ON schema_retired_column (retired_at) WHERE dropped_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON schema_retired_column TO attome_runtime;
GRANT SELECT ON schema_retired_column TO attome_readonly;
