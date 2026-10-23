-- M7-T1: every stage move a record makes under its entity's stage process:
-- the record, from and to, who, when, and the reason the request gave.
CREATE TABLE IF NOT EXISTS stage_move (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    from_stage text,
    to_stage text NOT NULL,
    moved_by uuid,
    moved_at timestamptz NOT NULL DEFAULT now(),
    reason text
);

CREATE INDEX IF NOT EXISTS stage_move_record_idx
    ON stage_move (entity_logicalname, record_id, moved_at DESC);

GRANT SELECT, INSERT ON stage_move TO attome_runtime;
GRANT SELECT ON stage_move TO attome_readonly;
