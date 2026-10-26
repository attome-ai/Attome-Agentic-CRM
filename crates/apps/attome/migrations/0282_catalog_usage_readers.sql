-- L4-T5: the nightly catalogue usage rollup also keeps who reads each entity
-- (readers by kind, from the metadata references) and whether it is unused
-- (no write in 90 days, no search in 30 and no reader).
SET LOCAL lock_timeout = '5s';

ALTER TABLE catalog_usage_rollup ADD COLUMN IF NOT EXISTS readers jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE catalog_usage_rollup ADD COLUMN IF NOT EXISTS unused boolean NOT NULL DEFAULT false;
