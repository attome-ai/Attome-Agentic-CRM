-- B17-T3: the device registry. One row per installed app or browser a
-- person signs in from, for remote wipe, offline status (B18) and push
-- notifications (J12).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS user_device (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES user_account(id) ON DELETE CASCADE,
    platform text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
    app_kind text NOT NULL CHECK (app_kind IN ('standard', 'branded', 'pwa')),
    app_version text NOT NULL CHECK (char_length(app_version) BETWEEN 1 AND 50),
    label text CHECK (char_length(label) <= 200),
    wipe_requested_at timestamptz,
    wiped_at timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    row_version bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS user_device_user_idx ON user_device (user_id);
CREATE INDEX IF NOT EXISTS user_device_last_seen_idx ON user_device (last_seen_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_device TO attome_runtime;
GRANT SELECT ON user_device TO attome_readonly;
