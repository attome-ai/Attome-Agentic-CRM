-- Q8-T1: session limits per role (NULL: the deployment default) and what a
-- session family records about its device and activity.
ALTER TABLE role_auth_policy
    ADD COLUMN IF NOT EXISTS idle_timeout_secs integer,
    ADD COLUMN IF NOT EXISTS absolute_lifetime_secs integer,
    ADD COLUMN IF NOT EXISTS max_sessions integer,
    ADD COLUMN IF NOT EXISTS max_sessions_mode text
        CHECK (max_sessions_mode IN ('end_oldest', 'refuse_new'));

ALTER TABLE refresh_token
    ADD COLUMN IF NOT EXISTS idle_secs integer,
    ADD COLUMN IF NOT EXISTS absolute_secs integer,
    ADD COLUMN IF NOT EXISTS last_activity_at timestamptz,
    ADD COLUMN IF NOT EXISTS user_agent text,
    ADD COLUMN IF NOT EXISTS device_label text,
    ADD COLUMN IF NOT EXISTS client_kind text NOT NULL DEFAULT 'web'
        CHECK (client_kind IN ('web', 'mobile', 'agent')),
    ADD COLUMN IF NOT EXISTS sign_in_method text;

-- Live sessions per person, for the session limit.
CREATE INDEX IF NOT EXISTS refresh_token_live_family_idx
    ON refresh_token (user_ref, family_id) WHERE revoked_at IS NULL AND used_at IS NULL;
