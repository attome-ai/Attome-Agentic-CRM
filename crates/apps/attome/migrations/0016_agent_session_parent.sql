-- N8-T1: one run tree. A session a supervisor agent delegated to points at
-- the supervisor's session; a top-level session has none.
ALTER TABLE agent_session ADD COLUMN IF NOT EXISTS parent_session_ref uuid REFERENCES agent_session(id);
CREATE INDEX IF NOT EXISTS agent_session_parent_idx ON agent_session (parent_session_ref) WHERE parent_session_ref IS NOT NULL;
