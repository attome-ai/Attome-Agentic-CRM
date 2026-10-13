-- Accounts and credentials (attome-auth), squashed from v1's final schema.
--
-- `user_account` holds what signing in needs: email, password hash, the
-- account state, and `auth_epoch`, which every session and API key checks so
-- one increment revokes all of them. Profile fields (names, language, theme)
-- belong to the engine's user record, not here (V2-D482).
--
-- Every secret column holds a hash or ciphertext, never the secret: tokens
-- are `public_id` + `secret_hash` pairs (the public part finds the row, the
-- peppered hash proves the secret), MFA seeds are envelope-encrypted, and
-- recovery codes are hashed.

-- Staff accounts. Customers sign in as contacts through the portal and never
-- share this table (V2-D95).
CREATE TABLE IF NOT EXISTS user_account (
    id             UUID        PRIMARY KEY DEFAULT uuidv7(),
    email          TEXT        NOT NULL,
    user_name      TEXT,
    password_hash  TEXT,
    google_sub     TEXT,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    email_verified BOOLEAN     NOT NULL DEFAULT FALSE,
    auth_epoch     INTEGER     NOT NULL DEFAULT 0,
    last_login     TIMESTAMPTZ,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_version    BIGINT      NOT NULL DEFAULT 0
);

-- An address or Google subject is unique among active accounts only, so a
-- deactivated account's address can be reused. Emails are stored canonical
-- (`attome_auth::email_identity::normalize_email`), so equality suffices.
CREATE UNIQUE INDEX IF NOT EXISTS user_account_email_active_unique
    ON user_account (email) WHERE is_active;
CREATE UNIQUE INDEX IF NOT EXISTS user_account_google_sub_active_unique
    ON user_account (google_sub) WHERE is_active AND google_sub IS NOT NULL;

-- Federated sign-in links (OIDC): one row per provider subject.
CREATE TABLE IF NOT EXISTS user_identity (
    id           UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref     UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider_key TEXT        NOT NULL,
    provider_sub TEXT        NOT NULL,
    email        TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_identity_provider_sub_unique UNIQUE (provider_key, provider_sub)
);
CREATE INDEX IF NOT EXISTS user_identity_user_ref_idx ON user_identity (user_ref);

-- Refresh tokens rotate within a family: using one marks it used and links
-- its successor, and reusing a used token revokes the whole family.
-- `family_started_at` caps a family's absolute lifetime; `auth_time`, `amr`
-- and `elevated_until` carry how and when the session authenticated, for
-- step-up.
CREATE TABLE IF NOT EXISTS refresh_token (
    id                UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref          UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    public_id         UUID        NOT NULL,
    secret_hash       TEXT        NOT NULL,
    family_id         UUID        NOT NULL,
    family_started_at TIMESTAMPTZ NOT NULL,
    used_at           TIMESTAMPTZ,
    replaced_by_ref   UUID        REFERENCES refresh_token (id),
    auth_time         TIMESTAMPTZ,
    amr               TEXT[],
    elevated_until    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked_at        TIMESTAMPTZ,
    CONSTRAINT refresh_token_public_id_unique UNIQUE (public_id)
);
CREATE INDEX IF NOT EXISTS refresh_token_user_ref_idx ON refresh_token (user_ref);
CREATE INDEX IF NOT EXISTS refresh_token_family_id_idx ON refresh_token (family_id);

-- Single-use tokens: password reset, email verification, invitation.
CREATE TABLE IF NOT EXISTS password_reset_token (
    id          UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref    UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    public_id   UUID        NOT NULL,
    secret_hash TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    CONSTRAINT password_reset_token_public_id_unique UNIQUE (public_id)
);
CREATE INDEX IF NOT EXISTS password_reset_token_user_ref_idx ON password_reset_token (user_ref);

CREATE TABLE IF NOT EXISTS email_verification_token (
    id          UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref    UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    public_id   UUID        NOT NULL,
    secret_hash TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    CONSTRAINT email_verification_token_public_id_unique UNIQUE (public_id)
);
CREATE INDEX IF NOT EXISTS email_verification_token_user_ref_idx
    ON email_verification_token (user_ref);

CREATE TABLE IF NOT EXISTS invitation_token (
    id             UUID        PRIMARY KEY DEFAULT uuidv7(),
    email          TEXT        NOT NULL,
    invited_by_ref UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    public_id      UUID        NOT NULL,
    secret_hash    TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,
    CONSTRAINT invitation_token_public_id_unique UNIQUE (public_id)
);
CREATE INDEX IF NOT EXISTS invitation_token_email_idx ON invitation_token (lower(email));
CREATE INDEX IF NOT EXISTS invitation_token_invited_by_ref_idx ON invitation_token (invited_by_ref);

-- TOTP enrolment. `last_accepted_totp_step` refuses a replayed code within
-- its validity window.
CREATE TABLE IF NOT EXISTS user_mfa (
    id                      UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref                UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    secret_encrypted        TEXT        NOT NULL,
    confirmed_at            TIMESTAMPTZ,
    last_accepted_totp_step BIGINT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_version             BIGINT      NOT NULL DEFAULT 0,
    is_deleted              BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_user_ref_active_unique
    ON user_mfa (user_ref) WHERE is_deleted = FALSE;

CREATE TABLE IF NOT EXISTS user_mfa_recovery_code (
    id         UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref   UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS user_mfa_recovery_code_user_ref_idx ON user_mfa_recovery_code (user_ref);

-- API keys: `public_key` finds the row, `secret_hash` (peppered, versioned)
-- proves the secret. A key acts as its user and dies with the user's
-- `auth_epoch`.
CREATE TABLE IF NOT EXISTS api_key (
    id           UUID        PRIMARY KEY DEFAULT uuidv7(),
    user_ref     UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    public_key   TEXT        NOT NULL,
    secret_hash  TEXT        NOT NULL,
    ip_allowlist TEXT[],
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS api_key_public_key_active_unique
    ON api_key (public_key) WHERE is_active;
CREATE INDEX IF NOT EXISTS api_key_user_ref_idx ON api_key (user_ref);

-- Which pepper ids this deployment has used, and a fingerprint of each, so a
-- pepper silently changed under an existing id fails at boot instead of
-- invalidating every key hashed with it.
CREATE TABLE IF NOT EXISTS api_key_pepper_registry (
    pepper_id          INTEGER     PRIMARY KEY,
    secret_fingerprint TEXT        NOT NULL,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
