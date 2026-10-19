-- J12-T1: where to push a person's notifications. A browser's Web Push
-- subscription (its endpoint and the keys its messages are encrypted to), or
-- an iOS (APNs) or Android (FCM) device token. One address belongs to one
-- person: registering it again moves it. A provider's "gone" answer deletes
-- the row.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS push_subscription (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    device_id uuid REFERENCES user_device (id) ON DELETE CASCADE,
    platform text NOT NULL CHECK (platform IN ('web', 'ios', 'android')),
    -- The Web Push endpoint URL, or the APNs/FCM device token.
    address text NOT NULL CHECK (char_length(address) BETWEEN 1 AND 4096),
    -- Web Push only: the browser's P-256 public key and auth secret,
    -- base64url as the browser gives them.
    p256dh text,
    auth text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((platform = 'web') = (p256dh IS NOT NULL AND auth IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS push_subscription_address_uq ON push_subscription (address);
CREATE INDEX IF NOT EXISTS push_subscription_user_idx ON push_subscription (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON push_subscription TO attome_runtime;
GRANT SELECT ON push_subscription TO attome_readonly;
