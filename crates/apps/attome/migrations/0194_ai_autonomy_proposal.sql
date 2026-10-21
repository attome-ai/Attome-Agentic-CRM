-- AH8-T9 (V2-D693): earned autonomy. When an agent's trial decisions for an
-- action agree with what people did often enough, the trial job proposes
-- raising that action's autonomy level by one; an administrator accepts or
-- rejects it. One open proposal per agent and action.
CREATE TABLE IF NOT EXISTS ai_autonomy_proposal (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_definition_id uuid NOT NULL,
    action_id text NOT NULL CHECK (char_length(action_id) BETWEEN 1 AND 200),
    -- The stored level code the proposal starts from; NULL is the built-in rule.
    from_level smallint CHECK (from_level IS NULL OR from_level BETWEEN 0 AND 5),
    to_level smallint NOT NULL CHECK (to_level BETWEEN 0 AND 5),
    agreement double precision NOT NULL CHECK (agreement BETWEEN 0 AND 1),
    cases integer NOT NULL CHECK (cases > 0),
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'accepted', 'rejected', 'expired')),
    expires_at timestamptz NOT NULL,
    decided_by uuid,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ai_autonomy_proposal_one_open_uq
    ON ai_autonomy_proposal (agent_definition_id, action_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS ai_autonomy_proposal_agent_idx
    ON ai_autonomy_proposal (agent_definition_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE ON ai_autonomy_proposal TO attome_runtime;
