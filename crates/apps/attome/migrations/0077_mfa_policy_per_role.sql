-- Q5-T1: second-factor policy per role, the grace period a person gets
-- once a factor becomes required, and remembered devices.
ALTER TABLE role_auth_policy
    ADD COLUMN IF NOT EXISTS mfa_mode text NOT NULL DEFAULT 'inherit'
        CHECK (mfa_mode IN ('inherit', 'off', 'optional', 'required')),
    ADD COLUMN IF NOT EXISTS mfa_factors text[] NOT NULL DEFAULT '{passkey,push,totp,recovery}',
    ADD COLUMN IF NOT EXISTS mfa_grace_days integer NOT NULL DEFAULT 7,
    ADD COLUMN IF NOT EXISTS remember_device_days integer NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS phishing_resistant_only boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS user_mfa_grace (
    user_ref uuid PRIMARY KEY REFERENCES user_account (id) ON DELETE CASCADE,
    required_since timestamptz NOT NULL,
    postpone_until timestamptz
);

CREATE TABLE IF NOT EXISTS remembered_device (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_ref uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    auth_epoch integer NOT NULL,
    label text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS remembered_device_user_live_idx
    ON remembered_device (user_ref) WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa_grace, remembered_device TO attome_runtime;
