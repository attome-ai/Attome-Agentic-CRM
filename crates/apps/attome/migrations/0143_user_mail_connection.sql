-- D15-T1: a person's own connection to their Microsoft 365 or Google
-- mailbox and calendar. Tokens are envelope-encrypted and bound to their row
-- (Q18) under integration.credential_encryption_key; nothing here is ever
-- returned in clear. A pending row holds one sign-in's PKCE verifier for ten
-- minutes, until the provider sends the person back.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS user_mail_connection (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    account_email text,
    scopes text NOT NULL DEFAULT '',
    access_token_enc text NOT NULL,
    refresh_token_enc text,
    expires_at timestamptz NOT NULL,
    connected_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, provider)
);

CREATE TABLE IF NOT EXISTS user_mail_connection_pending (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    code_verifier text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_mail_connection_pending_created_idx
    ON user_mail_connection_pending (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_mail_connection, user_mail_connection_pending
    TO attome_runtime;
GRANT SELECT ON user_mail_connection TO attome_readonly;
