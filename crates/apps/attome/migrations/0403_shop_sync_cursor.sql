-- F8-T5: where each shop connection's sync stopped, per kind of record, so the
-- next run (a webhook's, or the 15-minute one) goes on from there. The cursor
-- moves only after the page it names was written (attome_sales::shop_run).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS shop_sync_cursor (
    connection_id uuid        NOT NULL,
    source_kind   text        NOT NULL CHECK (source_kind IN ('order', 'customer', 'product')),
    cursor        text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, source_kind)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON shop_sync_cursor TO attome_runtime;
