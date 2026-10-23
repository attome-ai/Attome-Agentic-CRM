-- S11-T1: a server-to-server client may get short-lived access tokens from
-- the OAuth token endpoint (`POST /api/v1/oauth/token`), proving itself with
-- a JWT signed by its own key (private_key_jwt) or with a key's secret
-- (client_secret_basic). The public key that checks its assertions, and the
-- scopes a token may carry. A client with no key uses its secret only; one
-- with no scopes gets tokens with none.
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS oauth_public_key_pem text;
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS oauth_scopes text[] NOT NULL DEFAULT '{}';
