-- Z15-T12: customer tests. A customer test is a given/when/expect definition
-- run inside one transaction that is always rolled back; customer_test_run
-- keeps each run's outcome, written in its own short transaction afterwards.

CREATE TABLE IF NOT EXISTS customer_test (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    description text,
    definition jsonb NOT NULL,
    blocking boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid
);

CREATE TABLE IF NOT EXISTS customer_test_run (
    id uuid PRIMARY KEY,
    test_id uuid NOT NULL REFERENCES customer_test (id) ON DELETE CASCADE,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    passed boolean,
    failures jsonb
);

CREATE INDEX IF NOT EXISTS customer_test_run_test ON customer_test_run (test_id, started_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON customer_test TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON customer_test_run TO attome_runtime;
GRANT SELECT ON customer_test, customer_test_run TO attome_readonly;
