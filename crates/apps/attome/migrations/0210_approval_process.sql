-- M9-T1: approval processes. A process names an entity, an optional entry
-- condition (V2 rule text over the record's fields), the approval plan its
-- requests follow, and whether a submitted record is locked while its
-- request is pending (`lock_record`), except `editable_attributes`.
-- A submission is an ordinary `approval_request` with action type
-- `approval_process`, `regarding` the record, and `payload.process_id`.
CREATE TABLE IF NOT EXISTS approval_process (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL,
    entity_logicalname text NOT NULL,
    entry_condition text,
    plan jsonb NOT NULL,
    lock_record boolean NOT NULL DEFAULT true,
    editable_attributes text[] NOT NULL DEFAULT '{}',
    is_active boolean NOT NULL DEFAULT true,
    is_deleted boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS approval_process_entity_idx
    ON approval_process (entity_logicalname) WHERE NOT is_deleted;

-- The lock check on every update: a pending process request for the record.
CREATE INDEX IF NOT EXISTS approval_request_pending_process_idx
    ON approval_request (regarding_entity, regarding_id)
    WHERE status = 'pending' AND action_type = 'approval_process';

GRANT SELECT, INSERT, UPDATE, DELETE ON approval_process TO attome_runtime;
GRANT SELECT ON approval_process TO attome_readonly;
