-- T6-T2: customer-defined flags, read by rules and flows as flag('name').
-- A deployment's own state: defined and switched through the admin API, never
-- promoted. An emergency off forces the flag off until it is set again.
CREATE TABLE IF NOT EXISTS customer_flag (
    name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),
    description text,
    value boolean NOT NULL DEFAULT false,
    emergency_off boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    updated_by uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON customer_flag TO attome_runtime;
GRANT SELECT ON customer_flag TO attome_readonly;
