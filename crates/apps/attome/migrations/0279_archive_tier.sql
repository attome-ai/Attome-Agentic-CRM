-- L11-T1: the Parquet archive tier. Each file holds many archived records of
-- one entity and month (`archive-tier/{entity}/{yyyy}/{mm}/{file}.parquet`);
-- the index names the file that holds each archived record, and keeps the
-- restore once it happened.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS archive_tier_file (
    id uuid PRIMARY KEY,
    entity_logicalname text NOT NULL,
    period date NOT NULL,
    object_key text NOT NULL UNIQUE,
    checksum text NOT NULL,
    record_count integer NOT NULL CHECK (record_count >= 0),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS archive_tier_file_entity_period_idx
    ON archive_tier_file (entity_logicalname, period);

CREATE TABLE IF NOT EXISTS archive_tier_record (
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    file_ref uuid NOT NULL REFERENCES archive_tier_file (id),
    archived_by uuid NOT NULL,
    archived_at timestamptz NOT NULL DEFAULT now(),
    restored_by uuid,
    restored_at timestamptz,
    PRIMARY KEY (entity_logicalname, record_id)
);
CREATE INDEX IF NOT EXISTS archive_tier_record_file_idx ON archive_tier_record (file_ref);

GRANT SELECT, INSERT, UPDATE ON archive_tier_file, archive_tier_record TO attome_runtime;
GRANT SELECT ON archive_tier_file, archive_tier_record TO attome_readonly;
