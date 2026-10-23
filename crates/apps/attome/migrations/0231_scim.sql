-- Q3-T1: SCIM provisioning. One bearer token per identity provider, kept
-- only as a peppered hash, with an address allow-list; the IdP's external id
-- of each user account and team it provisioned, per token.
CREATE TABLE IF NOT EXISTS scim_token (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    public_id uuid NOT NULL UNIQUE,
    name text NOT NULL,
    secret_hash text NOT NULL,
    ip_allow text[] NOT NULL DEFAULT '{}',
    is_active boolean NOT NULL DEFAULT true,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

ALTER TABLE user_account ADD COLUMN IF NOT EXISTS scim_external_id text;
ALTER TABLE user_account ADD COLUMN IF NOT EXISTS scim_token_ref uuid;
CREATE UNIQUE INDEX IF NOT EXISTS user_account_scim_external_idx
    ON user_account (scim_token_ref, scim_external_id) WHERE scim_external_id IS NOT NULL;

ALTER TABLE team ADD COLUMN IF NOT EXISTS scim_external_id text;
ALTER TABLE team ADD COLUMN IF NOT EXISTS scim_token_ref uuid;
CREATE UNIQUE INDEX IF NOT EXISTS team_scim_external_idx
    ON team (scim_token_ref, scim_external_id) WHERE scim_external_id IS NOT NULL AND NOT is_deleted;

GRANT SELECT, INSERT, UPDATE ON scim_token TO attome_runtime;
