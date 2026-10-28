-- Q1-T9: which sign-in provider added a role or team membership through its
-- group mappings. A provider removes only the memberships it added (this
-- column names it); a membership an administrator gave has none and is never
-- touched. The membership tables are unique per person and role or team, so
-- an administrator's grant of the same role clears the column and takes the
-- membership over.
ALTER TABLE user_account_mm_role
    ADD COLUMN IF NOT EXISTS source_provider_ref uuid REFERENCES oidc_provider (id) ON DELETE SET NULL;
ALTER TABLE user_account_mm_team
    ADD COLUMN IF NOT EXISTS source_provider_ref uuid REFERENCES oidc_provider (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS user_account_mm_role_source_provider_idx
    ON user_account_mm_role (user_ref, source_provider_ref) WHERE source_provider_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS user_account_mm_team_source_provider_idx
    ON user_account_mm_team (user_ref, source_provider_ref) WHERE source_provider_ref IS NOT NULL;
