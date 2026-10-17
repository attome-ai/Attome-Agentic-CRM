-- F4-T3: invoicing's two infrastructure tables.
--
-- billing_invoice_request: an invoice another feature asks for (a won order,
-- a subscription charge, a project milestone), accepted once per source and
-- request key and turned into a draft invoice by the billing engine.
-- billing_posting_outbox: what an issue, credit, debit or write-off posts to
-- the ledger, read once by the ledger consumer. Neither holds metadata.

CREATE TABLE IF NOT EXISTS billing_invoice_request (
    id uuid PRIMARY KEY,
    source_kind text NOT NULL,
    source_ref text NOT NULL,
    idempotency_key text NOT NULL,
    account_ref uuid NOT NULL,
    currency text NOT NULL,
    request_date date NOT NULL,
    lines jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'invoiced', 'failed')),
    invoice_ref uuid,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_kind, idempotency_key)
);

CREATE INDEX IF NOT EXISTS billing_invoice_request_pending_idx
    ON billing_invoice_request (account_ref, currency, request_date)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS billing_posting_outbox (
    id uuid PRIMARY KEY,
    invoice_ref uuid NOT NULL,
    posting_kind text NOT NULL CHECK (posting_kind IN ('issue', 'credit', 'debit', 'write_off')),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz,
    consumer text
);

CREATE INDEX IF NOT EXISTS billing_posting_outbox_unconsumed_idx
    ON billing_posting_outbox (created_at)
    WHERE consumed_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON billing_invoice_request TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON billing_posting_outbox TO attome_runtime;
GRANT SELECT ON billing_invoice_request TO attome_readonly;
GRANT SELECT ON billing_posting_outbox TO attome_readonly;
