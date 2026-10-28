-- Q1-T4: what the provider admin shows about a client secret without ever
-- returning it: when it was last set, and the first 8 hex characters of its
-- SHA-256, so an administrator can tell which secret a provider holds.
SET LOCAL lock_timeout = '5s';

ALTER TABLE oidc_provider ADD COLUMN IF NOT EXISTS client_secret_updated_at timestamptz;
ALTER TABLE oidc_provider ADD COLUMN IF NOT EXISTS client_secret_fingerprint text;
