-- Q10-T8: conflicting-access rules. A pair of roles, privileges or
-- permission sets one person must not hold together: a grant that would
-- complete the pair is refused, or routed to a second administrator.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS role_conflict_rule (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    left_kind text NOT NULL CHECK (left_kind IN ('role', 'privilege', 'set')),
    left_ref uuid NOT NULL,
    right_kind text NOT NULL CHECK (right_kind IN ('role', 'privilege', 'set')),
    right_ref uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('refuse', 'approval')),
    reason text NOT NULL,
    created_by uuid,
    row_version bigint NOT NULL DEFAULT 0,
    is_deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((left_kind, left_ref) <> (right_kind, right_ref))
);
CREATE INDEX IF NOT EXISTS role_conflict_rule_live
    ON role_conflict_rule (left_kind, left_ref) WHERE is_deleted = false;

GRANT SELECT, INSERT, UPDATE ON role_conflict_rule TO attome_runtime;
