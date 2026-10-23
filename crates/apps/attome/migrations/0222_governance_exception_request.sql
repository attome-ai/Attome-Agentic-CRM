-- L3-T2: a policy exception's approval request (M9) and who asked for it.
ALTER TABLE governance_policy_exception
    ADD COLUMN IF NOT EXISTS approval_request_ref uuid,
    ADD COLUMN IF NOT EXISTS requested_by uuid,
    ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();

CREATE INDEX IF NOT EXISTS governance_policy_exception_policy_idx
    ON governance_policy_exception (policy_id);
