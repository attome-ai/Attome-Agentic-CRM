-- W1-T10: an approved contract sent for signature through a K4 envelope.
-- One open signing per contract; the contract_signature job ends a signing
-- when its envelope completes (the contract becomes active), is declined or
-- is voided.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS contract_signature (
    envelope_id  uuid        PRIMARY KEY,
    contract_id  uuid        NOT NULL,
    document_id  uuid        NOT NULL,
    requested_by uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    outcome      text        CHECK (outcome IN ('completed', 'declined', 'voided'))
);
CREATE UNIQUE INDEX IF NOT EXISTS contract_signature_open_idx
    ON contract_signature (contract_id) WHERE finished_at IS NULL;
CREATE INDEX IF NOT EXISTS contract_signature_contract_idx
    ON contract_signature (contract_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON contract_signature TO attome_runtime;
GRANT SELECT ON contract_signature TO attome_readonly;
