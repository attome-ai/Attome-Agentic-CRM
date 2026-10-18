-- Z4-T5: the session-token denylist when the deployment runs without Redis
-- (cache.backend = memory). The in-process store forgets on restart, which
-- would un-revoke every token revoked before it; this table does not. An
-- entry lives until the token it names would have expired; the auth token
-- prune job deletes the expired ones.
CREATE TABLE IF NOT EXISTS auth_jti_denylist (
    jti        uuid        PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_jti_denylist_expires_at_idx ON auth_jti_denylist (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_jti_denylist TO attome_runtime;
