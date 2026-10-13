-- Four-eyes approvals (attome-approval), squashed from v1's final schema.
--
-- A request names an action and its payload; approvers record grants until
-- `required_approvals` (or every step of `plan`) is met, then exactly one
-- executor claims it (`executing`, with who and when) and marks it
-- `executed`. `invalidated` means the thing being approved changed under the
-- request. `policy_id` and `regarding_*` are opaque references: the approval
-- crate never joins against the engine tables that own them.

CREATE TABLE IF NOT EXISTS approval_request (
    id                   UUID        PRIMARY KEY DEFAULT uuidv7(),
    action_type          TEXT        NOT NULL,
    payload              JSONB       NOT NULL,
    requested_by         UUID        NOT NULL,
    requested_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    status               TEXT        NOT NULL DEFAULT 'pending',
    required_approvals   INTEGER     NOT NULL DEFAULT 1 CHECK (required_approvals >= 1),
    plan                 JSONB,
    step                 INTEGER     NOT NULL DEFAULT 0 CHECK (step >= 0),
    step_started_at      TIMESTAMPTZ,
    escalated_at         TIMESTAMPTZ,
    policy_id            UUID,
    regarding_entity     TEXT,
    regarding_id         UUID,
    execution_claimed_at TIMESTAMPTZ,
    execution_claimed_by UUID,
    row_version          BIGINT      NOT NULL DEFAULT 0,
    expires_at           TIMESTAMPTZ NOT NULL,
    executed_at          TIMESTAMPTZ,

    CONSTRAINT approval_request_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'cancelled',
                          'invalidated', 'executing')),
    CONSTRAINT approval_request_execution_claim_check
        CHECK (status <> 'executing'
               OR (execution_claimed_at IS NOT NULL AND execution_claimed_by IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS approval_request_pending_idx
    ON approval_request (status, requested_at DESC)
    WHERE status = 'pending';
-- The expiry sweep.
CREATE INDEX IF NOT EXISTS approval_request_expiry_idx
    ON approval_request (expires_at)
    WHERE status = 'pending';
-- The step-timeout escalation sweep.
CREATE INDEX IF NOT EXISTS approval_request_step_timeout_idx
    ON approval_request (step_started_at)
    WHERE status = 'pending' AND plan IS NOT NULL;
CREATE INDEX IF NOT EXISTS approval_request_regarding_idx
    ON approval_request (regarding_entity, regarding_id)
    WHERE regarding_entity IS NOT NULL;

-- One decision per approver per step. `decided_by` differs from
-- `approver_id` when a delegate decides `on_behalf_of` the approver.
CREATE TABLE IF NOT EXISTS approval_grant (
    id           UUID        PRIMARY KEY DEFAULT uuidv7(),
    request_id   UUID        NOT NULL REFERENCES approval_request (id),
    approver_id  UUID        NOT NULL,
    step         INTEGER     NOT NULL DEFAULT 0,
    decision     TEXT        NOT NULL CHECK (decision IN ('approved', 'rejected')),
    decided_by   UUID,
    on_behalf_of UUID,
    signature    JSONB,
    comment      TEXT,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT approval_grant_request_step_approver_unique UNIQUE (request_id, step, approver_id)
);

CREATE INDEX IF NOT EXISTS approval_grant_request_idx ON approval_grant (request_id);
