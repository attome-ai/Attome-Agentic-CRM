-- Q1-T6: when a sign-in domain's DNS TXT record was last looked up, and why
-- that lookup did not verify it, for the administrator who asked.
ALTER TABLE oidc_domain ADD COLUMN IF NOT EXISTS last_checked_at timestamptz;
ALTER TABLE oidc_domain ADD COLUMN IF NOT EXISTS last_error text;
