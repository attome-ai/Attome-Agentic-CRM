-- AH8-T8 (V2-D693): what agents ran on their own. One row per action an agent
-- ran without a person deciding it at the time — its autonomy level was
-- act_and_report or automatic — so the person it acts for gets one daily
-- summary of the automatic ones (act_and_report already tells them per
-- action). The audit trail stays the record of what happened; this table only
-- feeds the summary, and the summary sweep prunes rows after 30 days.
CREATE TABLE IF NOT EXISTS ai_autonomous_run (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_session_id uuid NOT NULL,
    acting_user_id uuid NOT NULL,
    action_id text NOT NULL CHECK (char_length(action_id) BETWEEN 1 AND 200),
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 5),
    summarized_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_autonomous_run_unsummarized_idx
    ON ai_autonomous_run (acting_user_id, created_at) WHERE summarized_at IS NULL;
CREATE INDEX IF NOT EXISTS ai_autonomous_run_created_idx
    ON ai_autonomous_run (created_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_autonomous_run TO attome_runtime;
