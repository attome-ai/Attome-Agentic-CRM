-- Q10-T9: privilege use per person and day, and the removal proposals made
-- from it. Counts only; a proposal is a draft for a person to accept or
-- dismiss, never a change.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS privilege_usage_daily (
    day date NOT NULL,
    user_ref uuid NOT NULL,
    privilege_key text NOT NULL,
    uses bigint NOT NULL,
    PRIMARY KEY (day, user_ref, privilege_key)
);
CREATE INDEX IF NOT EXISTS privilege_usage_daily_key
    ON privilege_usage_daily (privilege_key, day);

CREATE TABLE IF NOT EXISTS privilege_removal_proposal (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    role_ref uuid NOT NULL REFERENCES role (id),
    privilege_key text NOT NULL,
    holders integer NOT NULL,
    last_used date,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'accepted', 'dismissed')),
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS privilege_removal_proposal_one_draft
    ON privilege_removal_proposal (role_ref, privilege_key) WHERE status = 'draft';

GRANT SELECT, INSERT, UPDATE, DELETE ON privilege_usage_daily TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON privilege_removal_proposal TO attome_runtime;
