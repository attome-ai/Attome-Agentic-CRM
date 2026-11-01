-- A1-T5: one index across every entity that extends a base, so a list of a
-- base's records ("all my work items") is one indexed read. Kept by the
-- attome-records/base-index change-feed consumer after each write commits;
-- rebuilt per base by the base_reindex job. A row per base an entity
-- descends from, at any depth.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS base_record_index (
    base       text        NOT NULL,
    id         uuid        NOT NULL,
    entity     text        NOT NULL,
    owner      uuid,
    status     text,
    due_at     timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (base, id)
);
CREATE INDEX IF NOT EXISTS base_record_index_owner_idx ON base_record_index (base, owner, due_at);
CREATE INDEX IF NOT EXISTS base_record_index_status_idx ON base_record_index (base, status);
CREATE INDEX IF NOT EXISTS base_record_index_entity_idx ON base_record_index (base, entity, due_at, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON base_record_index TO attome_runtime;
GRANT SELECT ON base_record_index TO attome_readonly;
