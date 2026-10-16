-- T6-T3: A/B variants of a feature flag. A subject's variant comes from a
-- stable hash, so it never changes while the split stays the same; each
-- outcome the product records is kept here, one row per event, for the
-- comparison of variants.
CREATE TABLE IF NOT EXISTS experiment_outcome (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    flag_key text NOT NULL,
    variant text NOT NULL,
    subject_id uuid NOT NULL,
    outcome text NOT NULL,
    value numeric,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS experiment_outcome_flag_idx
    ON experiment_outcome (flag_key, outcome, variant);

GRANT SELECT, INSERT ON experiment_outcome TO attome_runtime;
GRANT SELECT ON experiment_outcome TO attome_readonly;
