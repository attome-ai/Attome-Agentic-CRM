-- A1-T10: opt-in time travel per entity. An enabled entity keeps every
-- earlier version of a record in its own runtime-provisioned table
-- `<entity>__history`, partitioned by month on valid_to
-- (attome_records::time_travel). Set through
-- /api/v1/admin/time-travel/{entity}; retention_days NULL keeps history
-- for ever.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS entity_time_travel (
    entity_logicalname text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT false,
    retention_days integer CHECK (retention_days IS NULL OR retention_days > 0),
    row_version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid
);

GRANT SELECT, INSERT, UPDATE ON entity_time_travel TO attome_runtime;
GRANT SELECT ON entity_time_travel TO attome_readonly;
