-- AH7-T2: an agent's permission test runs: every generated case put
-- through the gate without executing anything, against the definition's
-- row version, with the cases the gate got wrong.
CREATE TABLE IF NOT EXISTS ai_permission_test_run (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_ref uuid NOT NULL,
    definition_row_version bigint NOT NULL,
    passed boolean NOT NULL,
    cases integer NOT NULL,
    failures jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NOT NULL
);

CREATE INDEX IF NOT EXISTS ai_permission_test_run_agent_idx
    ON ai_permission_test_run (agent_ref, created_at DESC);

GRANT SELECT, INSERT ON ai_permission_test_run TO attome_runtime;
GRANT SELECT ON ai_permission_test_run TO attome_readonly;
