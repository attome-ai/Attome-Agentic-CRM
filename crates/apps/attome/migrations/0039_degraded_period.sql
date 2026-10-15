-- AB5-T8: every degraded period: which capability went down, when, when it
-- came back, the features it affected and the probe's reason. One open row
-- per capability at most (ended_at IS NULL), so a node that sees the same
-- outage as another does not open a second one.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS degraded_period (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    capability text NOT NULL CHECK (char_length(capability) BETWEEN 1 AND 64),
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    features text[] NOT NULL,
    cause text CHECK (char_length(cause) <= 500),
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS degraded_period_one_open
    ON degraded_period (capability) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS degraded_period_started_idx ON degraded_period (started_at DESC);

GRANT SELECT, INSERT, UPDATE ON degraded_period TO attome_runtime;
GRANT SELECT ON degraded_period TO attome_readonly;
