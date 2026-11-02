-- O5-T1: next-best-action candidates. An action is offered on a record of
-- its entity when its rule-language condition holds, ranked by its weight
-- times the record's latest score from its propensity model (O1).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS nba_action (
    id uuid PRIMARY KEY,
    entity text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    name_ar text,
    condition text,
    model_ref uuid,
    weight double precision NOT NULL DEFAULT 1 CHECK (weight > 0),
    action jsonb NOT NULL DEFAULT '{}'::jsonb,
    is_active boolean NOT NULL DEFAULT true,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS nba_action_entity_name
    ON nba_action (entity, name) WHERE is_active;

GRANT SELECT, INSERT, UPDATE ON nba_action TO attome_runtime;
