-- M12-T3: a paused flow or report schedule. The flow target is
-- `{definition id}:{trigger node id}`, so a pause survives a republish; the
-- report target is the `report_schedule` id. The sweeps skip a paused
-- schedule until it is resumed (the row deleted).
CREATE TABLE IF NOT EXISTS schedule_pause (
    kind text NOT NULL CHECK (kind IN ('flow', 'report')),
    target text NOT NULL,
    paused_by uuid,
    paused_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, target)
);

GRANT SELECT, INSERT, DELETE ON schedule_pause TO attome_runtime;
GRANT SELECT ON schedule_pause TO attome_readonly;
