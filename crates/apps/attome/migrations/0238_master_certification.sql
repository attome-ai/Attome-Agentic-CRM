-- L1-T5: a golden record's certification, set by a data steward. A record
-- without a row is a draft.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS master_certification (
    entity text NOT NULL,
    golden_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'certified', 'retired')),
    set_by uuid NOT NULL,
    set_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, golden_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON master_certification TO attome_runtime;
GRANT SELECT ON master_certification TO attome_readonly;
