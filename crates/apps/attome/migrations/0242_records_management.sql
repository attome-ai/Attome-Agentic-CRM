-- K7-T1: records management. A record declared under a category becomes
-- immutable: the generic write path refuses its updates, deletes and
-- restores. It leaves only by erasure (when no legal hold applies) or by a
-- disposition a second person approves, which purges it and keeps a
-- certificate.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS records_category (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL UNIQUE,
    description text,
    retention_days integer CHECK (retention_days IS NULL OR retention_days > 0),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS record_declaration (
    entity text NOT NULL,
    record_id uuid NOT NULL,
    category_ref uuid NOT NULL REFERENCES records_category (id),
    declared_by uuid NOT NULL,
    declared_at timestamptz NOT NULL DEFAULT now(),
    disposed_at timestamptz,
    PRIMARY KEY (entity, record_id)
);

CREATE TABLE IF NOT EXISTS record_disposition (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity text NOT NULL,
    record_id uuid NOT NULL,
    category_ref uuid NOT NULL REFERENCES records_category (id),
    requested_by uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by uuid,
    reviewed_at timestamptz,
    reason text,
    certificate jsonb,
    certificate_sha256 text
);
CREATE UNIQUE INDEX IF NOT EXISTS record_disposition_one_pending
    ON record_disposition (entity, record_id) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE, DELETE ON records_category, record_declaration,
    record_disposition TO attome_runtime;
GRANT SELECT ON records_category, record_declaration, record_disposition TO attome_readonly;
