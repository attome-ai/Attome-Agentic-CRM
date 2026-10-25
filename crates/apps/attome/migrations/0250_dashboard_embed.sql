-- P8-T1: a dashboard embedded in another site. The embed names the sites
-- that may frame it and reads as its creator; viewer tokens are signed and
-- short-lived, so nothing about them is stored. Stopping an embed sets
-- revoked_at, which refuses every token already issued for it.
-- dashboard_id has no foreign key: attome_dashboard is a metadata-provisioned
-- table that a migration cannot assume exists.
CREATE TABLE IF NOT EXISTS dashboard_embed (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    dashboard_id uuid NOT NULL,
    allowed_origins text[] NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS dashboard_embed_dashboard_idx
    ON dashboard_embed (dashboard_id) WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON dashboard_embed TO attome_runtime;
GRANT SELECT ON dashboard_embed TO attome_readonly;
