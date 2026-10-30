-- T5-T1: a database made by `attome scratch create` carries one row here,
-- written into the copy only. Boot refuses to send real email from a
-- database with a row unless email test mode is set (Z8-T6). Empty on every
-- ordinary deployment.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sandbox_copy (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    source_database text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('full', 'metadata', 'sample')),
    masked_fields integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON sandbox_copy TO attome_runtime;
GRANT SELECT ON sandbox_copy TO attome_readonly;
