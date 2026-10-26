-- B1-T2: timeline entries pinned on a record, for everyone who may read it.
-- A pin names the entry (its kind and source row); reading a pinned entry
-- still goes through the timeline's own sources and permissions.
CREATE TABLE IF NOT EXISTS timeline_pin (
    entity_name text NOT NULL,
    record_id uuid NOT NULL,
    kind text NOT NULL,
    source_id uuid NOT NULL,
    pinned_by uuid NOT NULL,
    pinned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_name, record_id, kind, source_id)
);

GRANT SELECT, INSERT, DELETE ON timeline_pin TO attome_runtime;
GRANT SELECT ON timeline_pin TO attome_readonly;
