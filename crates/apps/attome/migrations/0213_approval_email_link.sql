-- M9-T3: emailed approval links. One link per approver and request step,
-- its secret stored only as a peppered HMAC, used once, expiring with the
-- request or after 72 hours. `approval_email_round` records that a step was
-- mailed, so a step with no reachable approver is not retried every minute.
CREATE TABLE IF NOT EXISTS approval_email_link (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    public_id uuid NOT NULL UNIQUE,
    secret_hash text NOT NULL,
    request_id uuid NOT NULL REFERENCES approval_request (id),
    approver_id uuid NOT NULL,
    step integer NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT approval_email_link_once UNIQUE (request_id, step, approver_id)
);

CREATE TABLE IF NOT EXISTS approval_email_round (
    request_id uuid NOT NULL REFERENCES approval_request (id),
    step integer NOT NULL,
    mailed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, step)
);

GRANT SELECT, INSERT, UPDATE ON approval_email_link TO attome_runtime;
GRANT SELECT, INSERT ON approval_email_round TO attome_runtime;
