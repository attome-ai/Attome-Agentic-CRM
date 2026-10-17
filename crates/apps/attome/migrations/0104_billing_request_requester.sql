-- F4-T9: who asked for an invoice request. The request sweep creates the
-- draft invoice as this person through the generic record path, so their
-- privileges and record scope apply as if they had created it by hand.

ALTER TABLE billing_invoice_request ADD COLUMN IF NOT EXISTS requested_by uuid;
