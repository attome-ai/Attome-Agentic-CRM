-- S11-T2: an S2S client trusts identity tokens from the customer's own
-- identity provider. A token from `issuer` whose audience holds `audience`
-- and whose `sub` is exactly `subject`, signed with a key from `jwks_uri`,
-- gets an access token for the client's service account at the OAuth token
-- endpoint (RFC 7523 jwt-bearer grant). One live trust per
-- (issuer, audience, subject).
CREATE TABLE IF NOT EXISTS s2s_federated_trust (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    client_ref uuid NOT NULL REFERENCES s2s_client (id),
    issuer text NOT NULL,
    audience text NOT NULL,
    subject text NOT NULL,
    jwks_uri text NOT NULL,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    is_deleted boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS s2s_federated_trust_live_uq
    ON s2s_federated_trust (issuer, audience, subject) WHERE NOT is_deleted;

CREATE INDEX IF NOT EXISTS s2s_federated_trust_client_idx
    ON s2s_federated_trust (client_ref) WHERE NOT is_deleted;

GRANT SELECT, INSERT, UPDATE ON s2s_federated_trust TO attome_runtime;
