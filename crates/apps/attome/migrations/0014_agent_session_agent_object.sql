-- V2-D487: the agent metadata object a session runs under, and the snapshot
-- of that agent's daily limits by class (limits.daily) taken at start.
ALTER TABLE agent_session ADD COLUMN IF NOT EXISTS agent_object_ref uuid;
ALTER TABLE agent_session ADD COLUMN IF NOT EXISTS daily_class_limits jsonb;
CREATE INDEX IF NOT EXISTS agent_session_agent_object_idx ON agent_session (agent_object_ref) WHERE agent_object_ref IS NOT NULL;
