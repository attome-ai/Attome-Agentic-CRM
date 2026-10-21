-- Z9-T5: one row per model call: who asked (the person, and the agent
-- session when an agent did), for which feature, which model answered, its
-- tokens, its cost in millionths of the price unit when the model has a
-- configured price, and how long the call took. Kept for reports and per-user
-- or per-feature spend; the token budgets themselves stay in Redis.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_usage_event (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    created_at timestamptz NOT NULL DEFAULT now(),
    user_id uuid NOT NULL,
    agent_session_id uuid,
    feature text NOT NULL,
    model_id text NOT NULL,
    prompt_tokens integer NOT NULL,
    completion_tokens integer NOT NULL,
    cached_prompt_tokens integer,
    reported boolean NOT NULL,
    cost_micros bigint,
    latency_ms integer NOT NULL
);

CREATE INDEX IF NOT EXISTS ai_usage_event_created_idx ON ai_usage_event (created_at);
CREATE INDEX IF NOT EXISTS ai_usage_event_user_idx ON ai_usage_event (user_id, created_at);
CREATE INDEX IF NOT EXISTS ai_usage_event_feature_idx ON ai_usage_event (feature, created_at);

GRANT SELECT, INSERT, DELETE ON ai_usage_event TO attome_runtime;
GRANT SELECT ON ai_usage_event TO attome_readonly;
