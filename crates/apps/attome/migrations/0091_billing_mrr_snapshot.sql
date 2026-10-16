-- F3-T10: the nightly recurring-revenue snapshot. One row per day, account
-- and currency with the monthly-normalised value of the subscription lines
-- in force that day, so recurring revenue and its movements read as of any
-- date. mrr_base stays NULL until exchange rates (A19) convert it.
CREATE TABLE IF NOT EXISTS billing_mrr_snapshot (
    day date NOT NULL,
    account_id uuid NOT NULL,
    currency text NOT NULL,
    mrr numeric NOT NULL,
    mrr_base numeric,
    PRIMARY KEY (day, account_id, currency)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON billing_mrr_snapshot TO attome_runtime;
GRANT SELECT ON billing_mrr_snapshot TO attome_readonly;
