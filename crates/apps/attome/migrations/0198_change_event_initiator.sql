-- AK3-T1: who drove each change event, a person (0) or an agent acting for
-- one (1, with its session), written from the same ambient attribution the
-- audit header uses (attome_core::agent_scope). The columns have constant
-- defaults, so adding them rewrites nothing; the check is NOT VALID because
-- every existing row already holds the default.
SET LOCAL lock_timeout = '5s';

ALTER TABLE entity_change_event
    ADD COLUMN IF NOT EXISTS initiator smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_session_id uuid;

ALTER TABLE entity_change_event DROP CONSTRAINT IF EXISTS entity_change_event_initiator_range;
ALTER TABLE entity_change_event
    ADD CONSTRAINT entity_change_event_initiator_range CHECK (initiator BETWEEN 0 AND 3) NOT VALID;
