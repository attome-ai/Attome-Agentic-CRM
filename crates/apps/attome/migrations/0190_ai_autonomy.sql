-- AH8 (V2-D693): agent autonomy levels and the undo window.
--
-- ai_autonomy_level: one row per (agent definition, action). No row keeps the
-- gate's built-in behaviour for that action; a row sets its level (0 suggest,
-- 1 ask first, 2 act with undo, 3 act and report, 4 automatic) and the limits
-- that hold at that level. Going over a limit asks first.
CREATE TABLE IF NOT EXISTS ai_autonomy_level (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_definition_id uuid NOT NULL,
    action_id text NOT NULL CHECK (char_length(action_id) BETWEEN 1 AND 200),
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 4),
    undo_seconds integer NOT NULL DEFAULT 300 CHECK (undo_seconds BETWEEN 30 AND 86400),
    daily_limit integer CHECK (daily_limit IS NULL OR daily_limit > 0),
    money_cap_minor bigint CHECK (money_cap_minor IS NULL OR money_cap_minor >= 0),
    currency text CHECK (currency IS NULL OR char_length(currency) = 3),
    owned_records_only boolean NOT NULL DEFAULT false,
    hours_start smallint CHECK (hours_start IS NULL OR hours_start BETWEEN 0 AND 23),
    hours_end smallint CHECK (hours_end IS NULL OR hours_end BETWEEN 1 AND 24),
    time_zone text CHECK (time_zone IS NULL OR char_length(time_zone) BETWEEN 1 AND 64),
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 1,
    CONSTRAINT ai_autonomy_level_money_has_currency
        CHECK ((money_cap_minor IS NULL) = (currency IS NULL)),
    CONSTRAINT ai_autonomy_level_hours_pair
        CHECK ((hours_start IS NULL) = (hours_end IS NULL)),
    CONSTRAINT ai_autonomy_level_hours_order
        CHECK (hours_start IS NULL OR hours_start < hours_end),
    CONSTRAINT ai_autonomy_level_one_per_action UNIQUE (agent_definition_id, action_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_autonomy_level TO attome_runtime;

-- ai_deferred_action: an action held for its undo window. A person or an
-- agent's level 2 puts it here; the deferred-action sweep runs it at run_at,
-- after re-checking it, unless someone cancelled it first. A row never runs
-- twice: `running` is claimed once, and one interrupted mid-run ends `failed`.
CREATE TABLE IF NOT EXISTS ai_deferred_action (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    action_id text NOT NULL CHECK (char_length(action_id) BETWEEN 1 AND 200),
    args jsonb NOT NULL,
    initiator text NOT NULL CHECK (initiator IN ('user', 'agent')),
    agent_session_id uuid,
    tool_call_id text CHECK (tool_call_id IS NULL OR char_length(tool_call_id) <= 200),
    acting_user_id uuid NOT NULL,
    target jsonb,
    report_to_owner boolean NOT NULL DEFAULT false,
    run_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'executed', 'cancelled', 'invalidated',
        'approval_required', 'failed')),
    attempts smallint NOT NULL DEFAULT 0,
    reason text CHECK (reason IS NULL OR char_length(reason) <= 500),
    result jsonb,
    approval_id uuid,
    cancelled_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_deferred_action_agent_has_session
        CHECK (initiator = 'user' OR agent_session_id IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS ai_deferred_action_tool_call_uq
    ON ai_deferred_action (agent_session_id, tool_call_id)
    WHERE tool_call_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ai_deferred_action_due_idx
    ON ai_deferred_action (run_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS ai_deferred_action_running_idx
    ON ai_deferred_action (updated_at) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS ai_deferred_action_user_idx
    ON ai_deferred_action (acting_user_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE ON ai_deferred_action TO attome_runtime;
