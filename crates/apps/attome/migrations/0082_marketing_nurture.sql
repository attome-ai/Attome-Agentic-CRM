-- E9-T2: nurture runtime state. Where each person stands in a programme,
-- which content they have already seen (so nothing is sent twice across
-- tracks), and the hand-offs to sales, one per score-threshold crossing.
CREATE TABLE IF NOT EXISTS marketing_nurture_state (
    program_id uuid NOT NULL,
    person_id uuid NOT NULL,
    enrolment_id uuid,
    track_id uuid,
    position integer NOT NULL DEFAULT 0,
    next_due_at timestamptz,
    paused_reason text,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'handed_off', 'exited')),
    PRIMARY KEY (program_id, person_id)
);
CREATE INDEX IF NOT EXISTS marketing_nurture_state_due_idx
    ON marketing_nurture_state (status, next_due_at) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS marketing_content_seen (
    person_id uuid NOT NULL,
    content_kind text NOT NULL,
    content_id text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (person_id, content_kind, content_id)
);

CREATE TABLE IF NOT EXISTS marketing_handoff (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    program_id uuid NOT NULL,
    person_id uuid NOT NULL,
    crossing_event_id uuid NOT NULL UNIQUE,
    score numeric,
    summary jsonb,
    assigned_to uuid,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'returned', 'overdue')),
    due_at timestamptz,
    decided_at timestamptz,
    return_reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS marketing_handoff_due_idx ON marketing_handoff (status, due_at);

-- Migrations run as the bootstrap role, so the migrator's default
-- privileges do not reach these tables.
GRANT SELECT, INSERT, UPDATE, DELETE
    ON marketing_nurture_state, marketing_content_seen, marketing_handoff TO attome_runtime;
GRANT SELECT ON marketing_nurture_state, marketing_content_seen, marketing_handoff
    TO attome_readonly;
