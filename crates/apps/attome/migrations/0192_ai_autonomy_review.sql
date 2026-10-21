-- AH8 (V2-D702): the `act_on_review` autonomy level. An agent's action at this
-- level is staged rather than run: it waits in ai_deferred_action with no
-- run_at until the person it acts for applies (or discards) the agent
-- session's staged actions together.
--
-- Stored codes stay stable: 0 suggest, 1 ask_first, 2 act_with_undo,
-- 3 act_and_report, 4 automatic, and 5 act_on_review (which ranks between
-- ask_first and act_with_undo; the ranking lives in code, not in the stored number).
ALTER TABLE ai_autonomy_level DROP CONSTRAINT IF EXISTS ai_autonomy_level_level_check;
ALTER TABLE ai_autonomy_level
    ADD CONSTRAINT ai_autonomy_level_level_check CHECK (level BETWEEN 0 AND 5);

ALTER TABLE ai_deferred_action ALTER COLUMN run_at DROP NOT NULL;
ALTER TABLE ai_deferred_action DROP CONSTRAINT IF EXISTS ai_deferred_action_status_check;
ALTER TABLE ai_deferred_action
    ADD CONSTRAINT ai_deferred_action_status_check CHECK (status IN (
        'staged', 'pending', 'running', 'executed', 'cancelled', 'invalidated',
        'approval_required', 'failed'));
ALTER TABLE ai_deferred_action DROP CONSTRAINT IF EXISTS ai_deferred_action_staged_has_no_run_at;
ALTER TABLE ai_deferred_action
    ADD CONSTRAINT ai_deferred_action_staged_has_no_run_at
        CHECK (status <> 'staged' OR run_at IS NULL);
-- Only a staged row (or one discarded while staged) has no run_at.
ALTER TABLE ai_deferred_action DROP CONSTRAINT IF EXISTS ai_deferred_action_run_at_set;
ALTER TABLE ai_deferred_action
    ADD CONSTRAINT ai_deferred_action_run_at_set
        CHECK (status IN ('staged', 'cancelled') OR run_at IS NOT NULL);
CREATE INDEX IF NOT EXISTS ai_deferred_action_staged_idx
    ON ai_deferred_action (agent_session_id, created_at) WHERE status = 'staged';
