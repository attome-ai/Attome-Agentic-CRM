-- B1-T1: the record timeline reads each source by record, newest first.
--
-- The audit sources (changes, state transitions and agent runs) filter on
-- (entity_name, record_id) and page by (changed_on DESC, id DESC); the older
-- idx_audit_header_entity_record leads with organization_ref and orders by
-- created_at, so it serves neither. Agent runs read only the rows an agent
-- wrote. Approvals are read by the record they regard.
CREATE INDEX IF NOT EXISTS audit_header_record_timeline_idx
    ON audit_header (entity_name, record_id, changed_on DESC, id DESC)
    WHERE changed_on IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_header_record_agent_idx
    ON audit_header (entity_name, record_id, agent_session_id)
    WHERE initiator = 1 AND changed_on IS NOT NULL;

CREATE INDEX IF NOT EXISTS approval_request_regarding_idx
    ON approval_request (regarding_entity, regarding_id, requested_at DESC, id DESC)
    WHERE regarding_entity IS NOT NULL;
