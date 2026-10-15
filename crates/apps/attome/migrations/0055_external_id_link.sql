-- A29-T3: the ids other systems know a record by, beyond the one each
-- external-id attribute holds. A merge moves the merged record's links to the
-- survivor and adds the merged record's own external ids, so a lookup by
-- either system's id still finds the survivor. One id per entity and system
-- points at one record.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS external_id_link (
    entity text NOT NULL,
    record_id uuid NOT NULL,
    system text NOT NULL,
    external_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, system, external_id)
);
CREATE INDEX IF NOT EXISTS external_id_link_record_idx ON external_id_link (entity, record_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON external_id_link TO attome_runtime;
GRANT SELECT ON external_id_link TO attome_readonly;
