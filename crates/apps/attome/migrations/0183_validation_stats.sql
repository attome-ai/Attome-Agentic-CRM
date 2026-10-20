-- A3-T8: every record write a business rule refused, and each entity's
-- nightly validity score.
--
-- `validation_rejection` is written in batches off the request path by
-- `attome_records::rejection_log`; overrides are security events instead
-- (A3-T4). `validation_score` is rewritten by `EngineJob::ValidationScoreSweep`.

CREATE TABLE IF NOT EXISTS validation_rejection (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    rule_ref    uuid NOT NULL,
    entity      text NOT NULL,
    attribute   text,
    channel     text NOT NULL,
    user_ref    uuid,
    rejected_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS validation_rejection_at_idx
    ON validation_rejection (rejected_at);
CREATE INDEX IF NOT EXISTS validation_rejection_rule_idx
    ON validation_rejection (rule_ref, rejected_at);

CREATE TABLE IF NOT EXISTS validation_score (
    entity      text PRIMARY KEY,
    checked     bigint NOT NULL,
    passing     bigint NOT NULL,
    unknown     bigint NOT NULL,
    score       double precision,
    computed_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON validation_rejection, validation_score TO attome_runtime;
GRANT SELECT ON validation_rejection, validation_score TO attome_readonly;
