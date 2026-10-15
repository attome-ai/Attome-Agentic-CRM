-- A16-T7: version conflicts (a write against a stale row version) per UTC
-- day, entity and source (api, bulk, import), so an admin sees where people
-- overwrite each other. One small row per day, entity and source.
CREATE TABLE IF NOT EXISTS conflict_daily_count (
    day date NOT NULL,
    entity text NOT NULL,
    source text NOT NULL,
    count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (day, entity, source)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON conflict_daily_count TO attome_runtime;
GRANT SELECT ON conflict_daily_count TO attome_readonly;
