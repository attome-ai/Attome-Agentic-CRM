-- AB3-T7: a declared disaster. Its actions (switch to the recovery site,
-- replace live data, fail back) wait on an approval a second person decides;
-- closing it records when it ended.
CREATE TABLE IF NOT EXISTS ops_disaster (
    id uuid PRIMARY KEY,
    declared_by uuid NOT NULL,
    declared_at timestamptz NOT NULL,
    scenario text NOT NULL,
    summary text NOT NULL,
    closed_at timestamptz,
    sla_excluded boolean NOT NULL DEFAULT false,
    exclusion_evidence text,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS ops_disaster_open_idx ON ops_disaster (declared_at DESC)
    WHERE closed_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON ops_disaster TO attome_runtime;
GRANT SELECT ON ops_disaster TO attome_readonly;
