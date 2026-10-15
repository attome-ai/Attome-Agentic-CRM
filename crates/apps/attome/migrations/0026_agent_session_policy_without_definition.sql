-- A session opened from a published v2 agent object (V2-D487) carries the
-- agent's policy without a v1 agent_definition row, so a policy no longer
-- implies a definition.
ALTER TABLE agent_session DROP CONSTRAINT IF EXISTS agent_session_policy_needs_definition;
