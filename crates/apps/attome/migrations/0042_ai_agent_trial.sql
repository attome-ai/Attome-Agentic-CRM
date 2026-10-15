-- AH6-T1: trial mode. A session marked trial runs its agent without
-- acting: each action it would have taken is kept here instead, to compare
-- with what the person actually did.
SET LOCAL lock_timeout = '5s';

ALTER TABLE agent_session ADD COLUMN IF NOT EXISTS trial boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS ai_trial_decision (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_session_id uuid NOT NULL REFERENCES agent_session(id) ON DELETE CASCADE,
    agent_ref uuid,
    action_id text NOT NULL,
    args jsonb NOT NULL,
    target_entity text,
    target_record_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    human_outcome text CHECK (human_outcome IN ('same', 'different', 'none')),
    compared_at timestamptz
);

CREATE INDEX IF NOT EXISTS ai_trial_decision_session_idx ON ai_trial_decision (agent_session_id, created_at);

GRANT SELECT, INSERT, UPDATE ON ai_trial_decision TO attome_runtime;
GRANT SELECT ON ai_trial_decision TO attome_readonly;
