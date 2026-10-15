-- L2-T1: data quality, second version. Rules per entity (and attribute) and
-- dimension with a weight; per entity (or domain) the dimension weights and
-- the target score; a score per record with its findings; a daily score per
-- entity and dimension. Issues gain an owner, a due date, a working status
-- and where the bad value came from.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS quality_rule (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity text NOT NULL,
    attribute text,
    dimension text NOT NULL,
    expression text NOT NULL,
    severity text NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'error')),
    weight numeric NOT NULL DEFAULT 1 CHECK (weight >= 0),
    enabled boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS quality_rule_entity_idx ON quality_rule (entity);

CREATE TABLE IF NOT EXISTS quality_target (
    entity text PRIMARY KEY,
    domain_ref uuid REFERENCES data_domain (id),
    dimension_weights jsonb NOT NULL DEFAULT '{}',
    threshold numeric NOT NULL DEFAULT 70 CHECK (threshold >= 0 AND threshold <= 100)
);

CREATE TABLE IF NOT EXISTS quality_record_score (
    entity text NOT NULL,
    record_id uuid NOT NULL,
    score numeric NOT NULL,
    findings jsonb NOT NULL DEFAULT '[]',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, record_id)
);

CREATE TABLE IF NOT EXISTS quality_snapshot (
    entity text NOT NULL,
    dimension text NOT NULL,
    day date NOT NULL,
    score numeric NOT NULL,
    PRIMARY KEY (entity, dimension, day)
);

ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS owner_id uuid;
ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS due_at timestamptz;
ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS accepted_reason text;
ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS source_channel text;
ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS source_import_id uuid;
ALTER TABLE quality_issue ADD COLUMN IF NOT EXISTS source_actor uuid;
-- The working statuses; `resolved` stays for the issues the sweep closes.
ALTER TABLE quality_issue DROP CONSTRAINT IF EXISTS quality_issue_status_check;
ALTER TABLE quality_issue ADD CONSTRAINT quality_issue_status_check
    CHECK (status IN ('open', 'in_progress', 'fixed', 'accepted', 'resolved'));

GRANT SELECT, INSERT, UPDATE, DELETE ON quality_rule, quality_target, quality_record_score,
    quality_snapshot TO attome_runtime;
GRANT SELECT ON quality_rule, quality_target, quality_record_score, quality_snapshot
    TO attome_readonly;
