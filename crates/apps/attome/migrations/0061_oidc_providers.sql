-- Q1-T2: sign-in providers an administrator manages on screen. An OpenID
-- Connect provider (its client secret encrypted), the email domains that
-- route to it (verified by a token, optionally SSO-only), the mapping from a
-- provider group claim to a team or a role, per role whether only SSO may
-- sign in, and the break-glass accounts exempt from that.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS oidc_provider (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    key text NOT NULL UNIQUE CHECK (key ~ '^[a-z0-9-]{2,40}$'),
    display_name text NOT NULL,
    display_name_ar text,
    preset text,
    issuer text NOT NULL,
    client_id text NOT NULL,
    client_secret_enc text NOT NULL,
    scopes text[] NOT NULL,
    claim_map jsonb NOT NULL DEFAULT '{}',
    link_mode text NOT NULL DEFAULT 'link_only' CHECK (link_mode IN ('link_only', 'create')),
    default_role_ref uuid REFERENCES role (id),
    trusted_for_mfa boolean NOT NULL DEFAULT true,
    tenant_allowlist text[] NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT true,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    is_deleted boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS oidc_domain (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    domain text NOT NULL UNIQUE CHECK (domain = lower(domain)),
    provider_ref uuid NOT NULL REFERENCES oidc_provider (id),
    verification_token text NOT NULL,
    verified_at timestamptz,
    sso_only boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_group_mapping (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    provider_ref uuid NOT NULL REFERENCES oidc_provider (id) ON DELETE CASCADE,
    claim_value text NOT NULL,
    team_ref uuid REFERENCES team (id),
    role_ref uuid REFERENCES role (id),
    CHECK ((team_ref IS NULL) <> (role_ref IS NULL)),
    UNIQUE (provider_ref, claim_value, team_ref, role_ref)
);

CREATE TABLE IF NOT EXISTS role_auth_policy (
    role_ref uuid PRIMARY KEY REFERENCES role (id) ON DELETE CASCADE,
    sso_only boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS break_glass_account (
    user_ref uuid PRIMARY KEY REFERENCES user_account (id) ON DELETE CASCADE,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_provider, oidc_domain, oidc_group_mapping,
    role_auth_policy, break_glass_account TO attome_runtime;
GRANT SELECT ON oidc_domain, oidc_group_mapping, role_auth_policy, break_glass_account
    TO attome_readonly;
