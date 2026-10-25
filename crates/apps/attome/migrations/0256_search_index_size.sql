-- A25-T5: the search index's size per entity, measured by the daily upkeep
-- of the drain loop and read by GET /api/v1/admin/search/status.
CREATE TABLE IF NOT EXISTS search_index_size (
    entity_logicalname text PRIMARY KEY,
    row_count bigint NOT NULL,
    bytes bigint NOT NULL,
    measured_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON search_index_size TO attome_runtime;
GRANT SELECT ON search_index_size TO attome_readonly;
