-- F6-T15: each customer update (a shipment leaving, out for delivery,
-- delivered; an order late) is decided once per subject and step, sent or
-- not, so a rerun of the change feed never messages a customer twice.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS fulfilment_customer_update (
    subject_id uuid NOT NULL,
    step text NOT NULL,
    contact_id uuid,
    -- queued, sent, no_consent, no_contact, no_template, failed
    status text NOT NULL,
    channels text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject_id, step)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON fulfilment_customer_update TO attome_runtime;
GRANT SELECT ON fulfilment_customer_update TO attome_readonly;
