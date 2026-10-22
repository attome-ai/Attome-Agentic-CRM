-- Z1-T11: the current OAuth 2.0 tokens of an integration system whose
-- auth_type is oauth2_client_credentials or oauth2_refresh_token, encrypted
-- under integration.credential_encryption_key (bound to the system id), and
-- the last refresh failure (masked text). No foreign key: integration_system
-- is provisioned at run time and does not exist when migrations run on a
-- fresh database. The application's own role only: tokens are secrets, so
-- the read-only role gets no grant.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS integration_oauth_token (
    system_id uuid PRIMARY KEY,
    access_token_encrypted text,
    refresh_token_encrypted text,
    expires_at timestamptz NOT NULL DEFAULT now(),
    last_refreshed_at timestamptz NOT NULL DEFAULT now(),
    last_refresh_error text,
    -- Set while one node refreshes, so others wait for its result instead of
    -- spending the refresh token twice; the HTTP call runs outside any
    -- transaction, and a crashed refresher's claim simply expires.
    refresh_claimed_until timestamptz,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS integration_oauth_token_expires_idx
    ON integration_oauth_token (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON integration_oauth_token TO attome_runtime;
