-- M10-T1: one table for every timer the platform keeps (a flow waiting
-- until a date, a reminder, an escalation). A sweep every 15 seconds claims
-- due timers with SKIP LOCKED and queues one job per timer, so each fires
-- once whatever runs at the same time.
CREATE TABLE IF NOT EXISTS timer (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    kind text NOT NULL,
    target_entity text,
    target_id uuid,
    run_id uuid,
    due_at timestamptz NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'fired', 'done', 'cancelled', 'failed')),
    fired_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS timer_status_due_idx ON timer (status, due_at);
CREATE INDEX IF NOT EXISTS timer_target_idx ON timer (target_entity, target_id)
    WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE, DELETE ON timer TO attome_runtime;
GRANT SELECT ON timer TO attome_readonly;
