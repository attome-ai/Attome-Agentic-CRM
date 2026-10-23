-- O9-T1: rule-change and flow-change scenarios: each run of the A3 rule
-- simulation or the M4 flow replay stored against a scenario, so runs can be
-- compared.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS scenario_simulation (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    scenario_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('rule_change', 'flow_change')),
    subject_id uuid NOT NULL,
    subject_version_id uuid,
    affected bigint NOT NULL,
    affected_ids uuid[] NOT NULL DEFAULT '{}',
    result jsonb NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scenario_simulation_scenario
    ON scenario_simulation (scenario_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON scenario_simulation TO attome_runtime;
GRANT SELECT ON scenario_simulation TO attome_readonly;
