-- L6-T4: personal data a profile found in an unlabelled attribute, as a
-- proposal for a builder to decide on. Counts only: no matched value is
-- stored. One open proposal per attribute and detector.
CREATE TABLE IF NOT EXISTS data_label_proposal (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    attribute text NOT NULL,
    detector text NOT NULL
        CHECK (detector IN ('saudi_national_id', 'iqama', 'iban', 'phone', 'email')),
    proposed_label text NOT NULL,
    matches bigint NOT NULL,
    sampled bigint NOT NULL,
    share_pct double precision NOT NULL,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    profile_ref uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS data_label_proposal_open_idx
    ON data_label_proposal (entity_logicalname, attribute, detector)
    WHERE status = 'open';

GRANT SELECT, INSERT, UPDATE ON data_label_proposal TO attome_runtime;
GRANT SELECT ON data_label_proposal TO attome_readonly;
