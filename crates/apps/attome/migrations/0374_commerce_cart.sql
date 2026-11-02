-- F7-T1: a portal member's cart. One open cart per portal user; lines keep
-- only the product and quantity, never a price: prices are resolved for the
-- account at checkout.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS commerce_cart (
    id uuid PRIMARY KEY,
    portal_user_id uuid NOT NULL,
    account_id uuid NOT NULL,
    -- open, ordered
    status text NOT NULL DEFAULT 'open',
    order_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS commerce_cart_open_idx
    ON commerce_cart (portal_user_id) WHERE status = 'open';

CREATE TABLE IF NOT EXISTS commerce_cart_line (
    cart_id uuid NOT NULL REFERENCES commerce_cart (id) ON DELETE CASCADE,
    product_id uuid NOT NULL,
    quantity numeric NOT NULL CHECK (quantity > 0),
    PRIMARY KEY (cart_id, product_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON commerce_cart, commerce_cart_line TO attome_runtime;
GRANT SELECT ON commerce_cart, commerce_cart_line TO attome_readonly;
