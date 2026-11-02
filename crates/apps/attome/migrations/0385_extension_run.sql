-- Y10-T6: one row per extension run: when, which version, how long, how
-- much fuel, the result and its log lines (secrets masked before they are
-- written). Kept for the extension's history and its test runs.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS extension_run (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    extension_name text NOT NULL,
    version integer NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    duration_ms integer NOT NULL CHECK (duration_ms >= 0),
    fuel_used bigint NOT NULL CHECK (fuel_used >= 0),
    ok boolean NOT NULL,
    error text,
    logs jsonb NOT NULL DEFAULT '[]'::jsonb,
    is_test boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS extension_run_by_name
    ON extension_run (extension_name, started_at DESC);

GRANT SELECT, INSERT ON extension_run TO attome_runtime;
