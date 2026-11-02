-- F8-T7: a guest checkout: the lines and phone it was started with, the
-- SHA-256 of its one-time code (never the code), wrong attempts, and, once
-- confirmed, the checkout key and the order it made. The key is unique per
-- portal, so a retried confirm finds the same order.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS commerce_guest_checkout (
    id uuid PRIMARY KEY,
    portal_id uuid NOT NULL,
    phone text NOT NULL,
    code_hash text NOT NULL,
    lines jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    checkout_key text,
    order_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS commerce_guest_checkout_phone_idx
    ON commerce_guest_checkout (phone, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS commerce_guest_checkout_key_idx
    ON commerce_guest_checkout (portal_id, checkout_key) WHERE checkout_key IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON commerce_guest_checkout TO attome_runtime;
GRANT SELECT ON commerce_guest_checkout TO attome_readonly;
