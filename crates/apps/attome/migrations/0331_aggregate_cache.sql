-- AA11-T1: the aggregate cache (attome_search::aggregate_cache). A dashboard
-- definition marked `cache` keeps its group-by result here under a key that
-- hashes the exact statement and its bound values, record filter included,
-- so only callers whose statement is the same share an entry. The labels of
-- lookup buckets are not kept: they are read per caller.
--
-- aggregate_cache_mark is the last time the change feed saw a change to an
-- entity (written by the `aggregate_cache_marks` job); an `on_change` entry
-- computed before it is not used. Not granted to attome_readonly: an entry
-- is computed under one caller's access and is read back only by the
-- engine for a caller with the same statement.
CREATE TABLE IF NOT EXISTS aggregate_cache (
    cache_key text PRIMARY KEY,
    entity_logicalname text NOT NULL,
    result jsonb NOT NULL,
    computed_at timestamptz NOT NULL,
    hits bigint NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS aggregate_cache_entity_idx
    ON aggregate_cache (entity_logicalname, computed_at);

CREATE TABLE IF NOT EXISTS aggregate_cache_mark (
    entity_logicalname text PRIMARY KEY,
    changed_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON aggregate_cache TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON aggregate_cache_mark TO attome_runtime;
