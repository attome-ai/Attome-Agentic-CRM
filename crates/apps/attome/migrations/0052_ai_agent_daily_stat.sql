-- AI8-T1: one row per agent and day: tasks done, resolved and measured, the
-- summed effectiveness, handoffs, tokens, cost and time saved. A derived
-- rollup, rebuildable from the outcome ledger, the action invocations and
-- the agent messages; nothing reads it as a source of truth for audit.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_agent_daily_stat (
    agent_definition_ref uuid NOT NULL,
    day date NOT NULL,
    tasks_done integer NOT NULL DEFAULT 0,
    tasks_resolved integer NOT NULL DEFAULT 0,
    tasks_measured integer NOT NULL DEFAULT 0,
    effectiveness_sum double precision NOT NULL DEFAULT 0,
    handoffs integer NOT NULL DEFAULT 0,
    input_tokens bigint NOT NULL DEFAULT 0,
    output_tokens bigint NOT NULL DEFAULT 0,
    cost_micros bigint NOT NULL DEFAULT 0,
    cost_unit text,
    time_saved_seconds bigint NOT NULL DEFAULT 0,
    computed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_definition_ref, day)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agent_daily_stat TO attome_runtime;
GRANT SELECT ON ai_agent_daily_stat TO attome_readonly;
