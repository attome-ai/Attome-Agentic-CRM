-- N23-T1: one run of an eval suite against its agent, and its graded result.
-- `status` is running until the background run finishes; a run whose process
-- died stays running and is superseded by the next one.
CREATE TABLE IF NOT EXISTS ai_eval_run (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    suite_ref uuid NOT NULL,
    suite_hash text NOT NULL,
    agent_ref uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'error')),
    score double precision,
    outcome jsonb,
    error text CHECK (error IS NULL OR char_length(error) <= 2000),
    started_by uuid NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS ai_eval_run_suite_idx ON ai_eval_run (suite_ref, started_at DESC);
CREATE INDEX IF NOT EXISTS ai_eval_run_agent_idx ON ai_eval_run (agent_ref, started_at DESC);
GRANT SELECT, INSERT, UPDATE ON ai_eval_run TO attome_runtime;
