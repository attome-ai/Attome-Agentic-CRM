-- A26-T1: derived entities. A derived entity is the anchor entity's rows
-- matching a rule-language condition, read-only, served from the view
-- `xrm_dv_<name>` (and, when stored, the membership table `xrm_dm_<name>`)
-- that provisioning creates. This table keeps the definitions.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS derived_entity (
    name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]{0,55}$'),
    anchor text NOT NULL,
    condition text NOT NULL CHECK (char_length(condition) BETWEEN 1 AND 4000),
    mode text NOT NULL DEFAULT 'live' CHECK (mode IN ('live', 'stored')),
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON derived_entity TO attome_runtime;
