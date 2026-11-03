-- S13-T1: the deployment's private package catalogue. Each row is one signed
-- package version, pushed or taken from a partner catalogue, waiting for
-- review by an administrator other than who added it; an approved version
-- installs through the package preview and metadata apply.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS package_catalogue (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    package_id    text NOT NULL,
    version       text NOT NULL,
    publisher     text NOT NULL,
    source        text NOT NULL,
    package       jsonb NOT NULL,
    permissions   jsonb NOT NULL DEFAULT '{}'::jsonb,
    review_status text NOT NULL DEFAULT 'pending'
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    review_note   text,
    added_by      uuid NOT NULL,
    reviewed_by   uuid,
    reviewed_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (package_id, version)
);

CREATE INDEX IF NOT EXISTS package_catalogue_created_idx
    ON package_catalogue (created_at DESC, id DESC);

GRANT SELECT, INSERT, UPDATE ON package_catalogue TO attome_runtime;
GRANT SELECT ON package_catalogue TO attome_readonly;
