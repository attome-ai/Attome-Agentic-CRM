-- F8-T9: whether an idle cart was handed to a journey (`emitted`, with
-- when) or skipped (`no_consent`); changing the cart clears both.
SET LOCAL lock_timeout = '5s';

ALTER TABLE commerce_cart ADD COLUMN IF NOT EXISTS abandoned_cart_outcome text;
ALTER TABLE commerce_cart ADD COLUMN IF NOT EXISTS abandoned_cart_notified_at timestamptz;

CREATE INDEX IF NOT EXISTS commerce_cart_abandoned_idx
    ON commerce_cart (updated_at) WHERE status = 'open' AND abandoned_cart_outcome IS NULL;
