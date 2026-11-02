-- AB11-T6: who follows the public status, and which notices each was sent.
-- A pending subscription keeps only the SHA-256 of its single-use confirm
-- token; the unsubscribe token is derived (an HMAC), so nothing is stored
-- for it.
--
-- 0314 created ops_status_subscriber ahead of this task with a stored
-- unsubscribe token and a `removed_at` flag; nothing read either. This
-- reshapes that table in place: the stored token and its index go, the
-- unique-address index goes with `removed_at` (a repeat public sign-up is a
-- new pending row, and a unique index would tell a stranger who already
-- subscribed), and the confirm token, unsubscribe stamp and creation columns
-- arrive.
SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS ops_status_subscriber_token_key;
DROP INDEX IF EXISTS ops_status_subscriber_address_key;

ALTER TABLE ops_status_subscriber
    DROP COLUMN IF EXISTS unsubscribe_token_hash,
    DROP COLUMN IF EXISTS removed_at,
    ADD COLUMN IF NOT EXISTS confirm_token_hash text,
    ADD COLUMN IF NOT EXISTS unsubscribed_at timestamptz,
    ADD COLUMN IF NOT EXISTS created_by uuid,
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE ops_status_subscriber
    DROP CONSTRAINT IF EXISTS ops_status_subscriber_address_length;
ALTER TABLE ops_status_subscriber
    ADD CONSTRAINT ops_status_subscriber_address_length
    CHECK (char_length(address) BETWEEN 1 AND 500);

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
