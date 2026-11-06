-- Y11-T13: a customer test can name the customisation it guards (a model
-- object: its kind and key, e.g. kind `form`, key `account.main`), so a
-- customisation's tests can be listed beside it. Both or neither.
ALTER TABLE customer_test ADD COLUMN IF NOT EXISTS target_kind text;
ALTER TABLE customer_test ADD COLUMN IF NOT EXISTS target_key text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'customer_test_target_both'
    ) THEN
        ALTER TABLE customer_test ADD CONSTRAINT customer_test_target_both
            CHECK ((target_kind IS NULL) = (target_key IS NULL));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS customer_test_target_idx
    ON customer_test (target_kind, target_key) WHERE target_kind IS NOT NULL;
