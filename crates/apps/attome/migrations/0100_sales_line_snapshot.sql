-- D6-T8: the lines of a deal before a bulk change (deal discount, quote
-- sync), kept so its author can undo the change within 30 minutes while
-- nothing has changed the lines since. A nightly job removes snapshots
-- older than a day.

CREATE TABLE IF NOT EXISTS sales_line_snapshot (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    parent_entity text NOT NULL,
    parent_id uuid NOT NULL,
    lines jsonb NOT NULL,
    row_versions jsonb NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at timestamptz
);
CREATE INDEX IF NOT EXISTS sales_line_snapshot_parent_idx
    ON sales_line_snapshot (parent_id, created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON sales_line_snapshot TO attome_runtime;
GRANT SELECT ON sales_line_snapshot TO attome_readonly;
