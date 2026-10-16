-- Z10-T1: what the approval engine's extensions store — the policy version
-- a request ran under, sub-requests, recall, skipped (conditional) steps,
-- reminders and escalation targets; evidence on a decision; versioned
-- policies; where a delegation came from; and agent recommendations.
-- The platform is not live yet, so the status check is replaced and
-- validated in one step.
ALTER TABLE approval_request
    ADD COLUMN IF NOT EXISTS policy_version integer,
    ADD COLUMN IF NOT EXISTS parent_request_id uuid REFERENCES approval_request (id),
    ADD COLUMN IF NOT EXISTS recalled_at timestamptz,
    ADD COLUMN IF NOT EXISTS skipped_steps integer[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS reminded_at timestamptz,
    ADD COLUMN IF NOT EXISTS escalated_to uuid;

ALTER TABLE approval_request DROP CONSTRAINT IF EXISTS approval_request_status_check;
ALTER TABLE approval_request ADD CONSTRAINT approval_request_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'cancelled',
                      'invalidated', 'executing', 'recalled'));

ALTER TABLE approval_grant
    ADD COLUMN IF NOT EXISTS attachments jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(attachments) = 'array'),
    ADD COLUMN IF NOT EXISTS evidence jsonb;

ALTER TABLE approval_policy ADD COLUMN IF NOT EXISTS current_version integer NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS approval_policy_version (
    policy_id uuid NOT NULL REFERENCES approval_policy (id),
    version integer NOT NULL,
    plan jsonb NOT NULL,
    condition text,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NOT NULL,
    PRIMARY KEY (policy_id, version)
);

INSERT INTO approval_policy_version (policy_id, version, plan, condition, created_by)
SELECT id, 1, plan, condition, created_by FROM approval_policy
ON CONFLICT DO NOTHING;

ALTER TABLE approval_delegation
    ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'manual'
        CHECK (source IN ('manual', 'leave', 'out_of_office'));

CREATE TABLE IF NOT EXISTS approval_recommendation (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    request_id uuid NOT NULL REFERENCES approval_request (id),
    step integer NOT NULL,
    recommended text NOT NULL CHECK (recommended IN ('approve', 'reject')),
    reasons text NOT NULL,
    agent_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS approval_recommendation_request_idx
    ON approval_recommendation (request_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON approval_policy_version, approval_recommendation
    TO attome_runtime;
GRANT SELECT ON approval_policy_version, approval_recommendation TO attome_readonly;
