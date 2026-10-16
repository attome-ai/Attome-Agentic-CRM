-- Q10-T6: a role grant may end on a date, with the reason it was given.
-- An hourly job removes grants past their end, the same way an
-- administrator removing the role does.
ALTER TABLE user_account_mm_role
    ADD COLUMN IF NOT EXISTS valid_until timestamptz,
    ADD COLUMN IF NOT EXISTS grant_reason text;

CREATE INDEX IF NOT EXISTS user_account_mm_role_valid_until_idx
    ON user_account_mm_role (valid_until)
    WHERE valid_until IS NOT NULL AND is_deleted = false;
