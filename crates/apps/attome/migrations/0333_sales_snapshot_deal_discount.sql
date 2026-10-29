-- D6-T11: undoing a deal discount puts the deal discount back too. A
-- snapshot taken by a deal discount keeps the percent the deal had before
-- (NULL for none); `deal_discount_saved` says the snapshot carries it, so a
-- quote sync's snapshot leaves the deal's discount alone.

ALTER TABLE sales_line_snapshot ADD COLUMN IF NOT EXISTS deal_discount_percent numeric;
ALTER TABLE sales_line_snapshot
    ADD COLUMN IF NOT EXISTS deal_discount_saved boolean NOT NULL DEFAULT false;
