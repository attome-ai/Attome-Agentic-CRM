-- M1-T2: one row per started slot of a schedule-triggered workflow. The
-- primary key is the at-most-once claim: only the sweep whose insert lands
-- starts the flow for that slot.
CREATE TABLE IF NOT EXISTS workflow_schedule_slot (
    definition_version_id uuid NOT NULL
        REFERENCES workflow_definition_version (id) ON DELETE CASCADE,
    node_id text NOT NULL,
    slot_at timestamptz NOT NULL,
    instance_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (definition_version_id, node_id, slot_at)
);

CREATE INDEX IF NOT EXISTS workflow_schedule_slot_created_at_idx
    ON workflow_schedule_slot (created_at);
