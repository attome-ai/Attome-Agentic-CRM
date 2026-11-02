-- A26-T2: maintaining stored derived entities from the change feed. A
-- definition can be paused by the surge guard; while it is, the anchors
-- its changes touch wait in derived_entity_pending until an administrator
-- resumes it. Every member entering or leaving is a history row.
SET LOCAL lock_timeout = '5s';

ALTER TABLE derived_entity ADD COLUMN IF NOT EXISTS paused_at timestamptz;
ALTER TABLE derived_entity ADD COLUMN IF NOT EXISTS pause_reason text;

CREATE TABLE IF NOT EXISTS derived_entity_pending (
    name text NOT NULL,
    anchor_id uuid NOT NULL,
    PRIMARY KEY (name, anchor_id)
);

CREATE TABLE IF NOT EXISTS derived_entity_history (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL,
    anchor_id uuid NOT NULL,
    change text NOT NULL CHECK (change IN ('enter', 'leave')),
    reason text,
    at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS derived_entity_history_member
    ON derived_entity_history (name, anchor_id, at);

GRANT SELECT, INSERT, UPDATE, DELETE ON derived_entity_pending TO attome_runtime;
GRANT SELECT, INSERT ON derived_entity_history TO attome_runtime;
