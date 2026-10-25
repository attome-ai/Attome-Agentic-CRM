-- AB4-T7: when each kind of recovery drill is due. Nothing runs in the
-- server: the drill agent asks which drills are due and uploads their
-- evidence, which moves the schedule on. Every schedule starts disabled; the
-- monthly restore drill is proposed here and an administrator turns it on.
CREATE TABLE IF NOT EXISTS ops_drill_schedule (
    id uuid PRIMARY KEY,
    kind text NOT NULL UNIQUE,
    cadence text NOT NULL CHECK (cadence IN ('weekly', 'monthly', 'quarterly')),
    enabled boolean NOT NULL DEFAULT false,
    next_due_at timestamptz,
    last_run_id uuid,
    row_version bigint NOT NULL DEFAULT 1,
    updated_by uuid,
    updated_at timestamptz
);

INSERT INTO ops_drill_schedule (id, kind, cadence, enabled)
VALUES ('0192f5a0-0000-7000-8000-00000000ab47', 'restore', 'monthly', false)
ON CONFLICT DO NOTHING;

GRANT SELECT, UPDATE ON ops_drill_schedule TO attome_runtime;
GRANT SELECT ON ops_drill_schedule TO attome_readonly;
