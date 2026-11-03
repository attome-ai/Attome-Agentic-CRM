-- AH3-T2: every account says what kind of principal it is, once: 0 a person,
-- 1 a service (an S2S or integration account), 2 an agent (identity plan
-- AG-1: one identity table, the kind immutable). Existing accounts are
-- people; integration accounts move to service through the integration
-- admin path, never by hand (D-425). A change of kind is refused by the
-- trigger below, whoever writes it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE user_account ADD COLUMN IF NOT EXISTS principal_kind smallint NOT NULL DEFAULT 0;

DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_account_principal_kind_check'
    ) THEN
        ALTER TABLE user_account
            ADD CONSTRAINT user_account_principal_kind_check CHECK (principal_kind BETWEEN 0 AND 2);
    END IF;
END
$do$;

CREATE OR REPLACE FUNCTION user_account_principal_kind_keep() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.principal_kind IS DISTINCT FROM OLD.principal_kind THEN
        RAISE EXCEPTION 'an account''s principal kind never changes'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS user_account_principal_kind_keep ON user_account;
CREATE TRIGGER user_account_principal_kind_keep BEFORE UPDATE OF principal_kind ON user_account
    FOR EACH ROW EXECUTE FUNCTION user_account_principal_kind_keep();
