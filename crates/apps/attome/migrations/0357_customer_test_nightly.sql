-- T7-T3: customer tests marked live-safe run every night against the live
-- configuration (a test always rolls back, so the check is read-only). Each
-- run keeps the test and configuration versions it ran on, so a test whose
-- runs on one pair of versions both pass and fail is flagged flaky.
SET LOCAL lock_timeout = '5s';

ALTER TABLE customer_test
    ADD COLUMN IF NOT EXISTS live_safe boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS flaky_since timestamptz;

ALTER TABLE customer_test_run
    ADD COLUMN IF NOT EXISTS test_version bigint,
    ADD COLUMN IF NOT EXISTS config_version bigint,
    ADD COLUMN IF NOT EXISTS scheduled boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS customer_test_run_versions
    ON customer_test_run (test_id, test_version, config_version);
