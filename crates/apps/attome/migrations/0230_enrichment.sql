-- L9-T1: what enrichment sources propose for a record's fields, with the
-- source and when it was fetched (the field's provenance once accepted),
-- and each provider's calls per day against its budget. Enrichment never
-- writes a record; a proposal is accepted or rejected by a person.
CREATE TABLE IF NOT EXISTS enrichment_proposal (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    field text NOT NULL,
    current_value jsonb,
    proposed_value jsonb NOT NULL,
    kind text NOT NULL CHECK (kind IN ('fill', 'review')),
    source text NOT NULL,
    fetched_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    decided_by uuid,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS enrichment_proposal_pending_idx
    ON enrichment_proposal (entity_logicalname, record_id, field, source)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS enrichment_usage (
    provider text NOT NULL,
    day date NOT NULL,
    calls integer NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, day)
);

GRANT SELECT, INSERT, UPDATE ON enrichment_proposal, enrichment_usage TO attome_runtime;
GRANT SELECT ON enrichment_proposal, enrichment_usage TO attome_readonly;
