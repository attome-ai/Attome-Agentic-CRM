-- AI4-T1: the follow-up ledger. Each stall the follow-up scan finds (a deal
-- gone quiet, an overdue task, a customer waiting for an answer) is
-- recorded once per record and window, then followed from reminder to
-- draft to sent, dismissed or resolved. The outcome ledger gains the
-- `agent_task` kind and a link to the agent session that did the work.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_followup_item (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    rule_ref uuid NOT NULL,
    entity_logical_name text NOT NULL,
    record_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    reason text NOT NULL CHECK (reason IN ('stalled_deal', 'overdue_task', 'unanswered_customer')),
    window_start date NOT NULL,
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'reminded', 'drafted', 'sent', 'dismissed', 'resolved')),
    agent_session_ref uuid,
    outcome_ref uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 1,
    UNIQUE (rule_ref, record_id, window_start)
);

CREATE INDEX IF NOT EXISTS ai_followup_item_owner_idx ON ai_followup_item (owner_user_id, status);

ALTER TABLE outcome DROP CONSTRAINT IF EXISTS outcome_kind_chk;
ALTER TABLE outcome ADD CONSTRAINT outcome_kind_chk CHECK (
    kind IN ('ai_suggestion', 'decision', 'recommendation', 'prediction', 'classification', 'edge',
             'process_change', 'config_change', 'agent_task')
);
ALTER TABLE outcome ADD COLUMN IF NOT EXISTS agent_session_ref uuid;
CREATE INDEX IF NOT EXISTS outcome_agent_session_idx ON outcome (agent_session_ref)
    WHERE agent_session_ref IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON ai_followup_item TO attome_runtime;
GRANT SELECT ON ai_followup_item TO attome_readonly;
