-- N30-T3: per-write approval policies, off by default. An active row makes an
-- agent's confirmed write of `action_id` (on `entity`, or on any entity when
-- it is null) wait for a second person's approval instead of running.
CREATE TABLE IF NOT EXISTS ai_write_approval_policy (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    action_id text NOT NULL CHECK (char_length(action_id) BETWEEN 1 AND 200),
    entity text CHECK (entity IS NULL OR char_length(entity) BETWEEN 1 AND 100),
    reason text CHECK (reason IS NULL OR char_length(reason) <= 500),
    is_active boolean NOT NULL DEFAULT true,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    deactivated_by uuid,
    deactivated_at timestamptz
);
CREATE INDEX IF NOT EXISTS ai_write_approval_policy_active_idx
    ON ai_write_approval_policy (action_id) WHERE is_active;
GRANT SELECT, INSERT, UPDATE ON ai_write_approval_policy TO attome_runtime;
