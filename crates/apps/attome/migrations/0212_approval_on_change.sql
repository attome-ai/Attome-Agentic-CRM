-- M9-T2: an approval process starts on `submit` (M9-T1) or on `change`:
-- an update that changes one of `watched_attributes`, on a record meeting
-- the entry condition, keeps the stored values and opens an
-- `approval_process.change` request carrying the held values, written when
-- it is approved.
ALTER TABLE approval_process
    ADD COLUMN IF NOT EXISTS starts_on text NOT NULL DEFAULT 'submit';
ALTER TABLE approval_process
    ADD COLUMN IF NOT EXISTS watched_attributes text[] NOT NULL DEFAULT '{}';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'approval_process_starts_on_check') THEN
        ALTER TABLE approval_process
            ADD CONSTRAINT approval_process_starts_on_check CHECK (starts_on IN ('submit', 'change'));
    END IF;
END $$;

-- The probe on every update: the entity's active `change` processes.
CREATE INDEX IF NOT EXISTS approval_process_change_idx
    ON approval_process (entity_logicalname)
    WHERE starts_on = 'change' AND is_active AND NOT is_deleted;

-- One pending held change per record and process.
CREATE INDEX IF NOT EXISTS approval_request_pending_change_idx
    ON approval_request (regarding_entity, regarding_id)
    WHERE status = 'pending' AND action_type = 'approval_process.change';
