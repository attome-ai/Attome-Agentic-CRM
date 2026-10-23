-- L7-T2: where a change came from. `channel` is the path the write arrived
-- through (`flow`, `job`; NULL for an ordinary request) and `flow_run_id`
-- the workflow instance whose step made it, so a subscriber can skip a
-- flow's echo of its own update. Who made it is `initiator` /
-- `agent_session_id`; what changed is `changed_attributes` / `before` /
-- `after` (0072); the transaction is `commit_xid`.
ALTER TABLE entity_change_event ADD COLUMN IF NOT EXISTS channel text;
ALTER TABLE entity_change_event ADD COLUMN IF NOT EXISTS flow_run_id uuid;
