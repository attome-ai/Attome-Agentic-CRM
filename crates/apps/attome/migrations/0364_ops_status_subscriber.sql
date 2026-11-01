-- AB11-T6: who follows the public status, and which notices each was sent.
-- A pending subscription keeps only the SHA-256 of its single-use confirm
-- token; the unsubscribe token is derived (an HMAC), so nothing is stored
-- for it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ops_status_subscriber (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    channel text NOT NULL CHECK (channel IN ('email', 'webhook')),
    address text NOT NULL CHECK (char_length(address) BETWEEN 1 AND 500),
    components text[] NOT NULL DEFAULT '{}',
    consent_at timestamptz NOT NULL,
    confirm_token_hash text,
    confirmed_at timestamptz,
    unsubscribed_at timestamptz,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ops_status_subscriber_confirm_token
    ON ops_status_subscriber (confirm_token_hash) WHERE confirm_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS ops_status_subscriber_active
    ON ops_status_subscriber (id) WHERE confirmed_at IS NOT NULL AND unsubscribed_at IS NULL;

CREATE TABLE IF NOT EXISTS ops_status_delivery (
    subscriber_id uuid NOT NULL REFERENCES ops_status_subscriber (id),
    item_key text NOT NULL CHECK (char_length(item_key) BETWEEN 1 AND 100),
    delivered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subscriber_id, item_key)
);

GRANT SELECT, INSERT, UPDATE ON ops_status_subscriber TO attome_runtime;
GRANT SELECT, INSERT, DELETE ON ops_status_delivery TO attome_runtime;
GRANT SELECT ON ops_status_subscriber, ops_status_delivery TO attome_readonly;
