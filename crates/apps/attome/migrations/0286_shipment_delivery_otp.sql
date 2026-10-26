-- F6-T11: the one-time code a customer gives the driver at delivery, when
-- `fulfilment.delivery.otp` is on. Only a salted SHA-256 of the code is kept;
-- it is replaced when the shipment goes out for delivery again and removed
-- once a delivery is proved. Five wrong codes lock it until a new one.
CREATE TABLE IF NOT EXISTS shipment_delivery_otp (
    shipment_id uuid PRIMARY KEY,
    code_hash text NOT NULL,
    failed_attempts integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON shipment_delivery_otp TO attome_runtime;
