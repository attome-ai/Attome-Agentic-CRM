-- S4-T9: a stored query may hold a QuerySpec and the typed parameters its
-- param conditions name ([{name, type, required}]), run by id through
-- query/run. The version row carries the pair it was published with.
ALTER TABLE sql_query
    ADD COLUMN IF NOT EXISTS query_spec JSONB NULL,
    ADD COLUMN IF NOT EXISTS parameters JSONB NULL;

ALTER TABLE sql_query_version
    ADD COLUMN IF NOT EXISTS query_spec JSONB NULL,
    ADD COLUMN IF NOT EXISTS parameters JSONB NULL;
