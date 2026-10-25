-- Z10-T11: a recommendation on an approval request: approve or reject and
-- why, from an eligible approver or an agent acting for one. A
-- recommendation decides nothing; only a decision does.
CREATE TABLE IF NOT EXISTS approval_recommendation (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    request_id uuid NOT NULL REFERENCES approval_request (id) ON DELETE CASCADE,
    recommended text NOT NULL CHECK (recommended IN ('approve', 'reject')),
    reasons text NOT NULL CHECK (char_length(reasons) BETWEEN 1 AND 2000),
    recommended_by uuid NOT NULL,
    agent_session uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS approval_recommendation_request_idx
    ON approval_recommendation (request_id, created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON approval_recommendation TO attome_runtime;
GRANT SELECT ON approval_recommendation TO attome_readonly;
