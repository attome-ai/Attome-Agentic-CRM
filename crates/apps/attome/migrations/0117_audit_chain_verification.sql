-- Q16-T2: each scheduled verification of an organization's audit chain,
-- with what it checked and any errors it found.
CREATE TABLE IF NOT EXISTS audit_chain_verification (
    id               uuid        PRIMARY KEY,
    organization_ref uuid        NOT NULL,
    verified_at      timestamptz NOT NULL DEFAULT now(),
    ok               boolean     NOT NULL,
    headers_checked  bigint      NOT NULL,
    batches_checked  bigint      NOT NULL,
    errors           jsonb       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_chain_verification_org_at_idx
    ON audit_chain_verification (organization_ref, verified_at DESC);

GRANT SELECT, INSERT ON audit_chain_verification TO attome_runtime;
GRANT SELECT ON audit_chain_verification TO attome_readonly;
