-- A4-T3: autonumber counters per sequence key and period. A rule whose
-- sequence key names record values (a branch, a document type) keeps one
-- counter per resolved key and per period (year, Hijri year, month, day), so
-- each branch numbers its own invoices and every counter restarts with its
-- period. The row is locked by the allocating transaction, so numbers stay
-- gap-free.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS autovalue_counter (
    rule_id uuid NOT NULL,
    sequence_key text NOT NULL,
    period_key text NOT NULL,
    next_value bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, sequence_key, period_key)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON autovalue_counter TO attome_runtime;
GRANT SELECT ON autovalue_counter TO attome_readonly;
