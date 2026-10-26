-- P13-T1: the manifest of the warehouse export: one row per Parquet file it
-- wrote under warehouse/{entity}/ in object storage. The object key is named
-- by the first and last change event the file holds, so a run repeated after
-- a crash finds its row already here.
CREATE TABLE IF NOT EXISTS warehouse_export_file (
    object_key text PRIMARY KEY,
    entity_logicalname text NOT NULL,
    hour timestamptz NOT NULL,
    schema_version text NOT NULL,
    columns jsonb NOT NULL,
    rows integer NOT NULL CHECK (rows >= 0),
    tombstones integer NOT NULL CHECK (tombstones >= 0),
    first_event_id uuid NOT NULL,
    last_event_id uuid NOT NULL,
    checksum text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS warehouse_export_file_entity_hour_idx
    ON warehouse_export_file (entity_logicalname, hour);

GRANT SELECT, INSERT, UPDATE, DELETE ON warehouse_export_file TO attome_runtime;
GRANT SELECT ON warehouse_export_file TO attome_readonly;
