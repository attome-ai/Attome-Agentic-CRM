-- L3-T1: data governance, second version. Domains nest (sub-domains); people
-- hold governance roles in a domain; a domain's policies (in Arabic and
-- English, versioned) name what enforces them (a check, a label, attribute
-- security, retention, residency); exceptions to a policy are approved and
-- expire; assets are certified against a hash of their definition.
SET LOCAL lock_timeout = '5s';

ALTER TABLE data_domain ADD COLUMN IF NOT EXISTS parent_ref uuid REFERENCES data_domain (id);

CREATE TABLE IF NOT EXISTS governance_role (
    domain_ref uuid NOT NULL REFERENCES data_domain (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'steward', 'deputy', 'custodian', 'consumer')),
    PRIMARY KEY (domain_ref, user_id, role)
);

CREATE TABLE IF NOT EXISTS governance_policy (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    domain_ref uuid NOT NULL REFERENCES data_domain (id),
    name_en text NOT NULL,
    name_ar text,
    body_en text NOT NULL DEFAULT '',
    body_ar text,
    version integer NOT NULL DEFAULT 1,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS governance_policy_enforcement (
    policy_id uuid NOT NULL REFERENCES governance_policy (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('check', 'label', 'attribute_security', 'retention', 'residency')),
    target_ref text NOT NULL,
    PRIMARY KEY (policy_id, kind, target_ref)
);

CREATE TABLE IF NOT EXISTS governance_policy_exception (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    policy_id uuid NOT NULL REFERENCES governance_policy (id),
    target_ref text NOT NULL,
    reason text NOT NULL,
    approved_by uuid,
    expires_at timestamptz,
    status text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'approved', 'rejected', 'expired'))
);

CREATE TABLE IF NOT EXISTS governance_certification (
    asset_kind text NOT NULL,
    asset_ref text NOT NULL,
    certified_by uuid,
    certified_at timestamptz NOT NULL DEFAULT now(),
    definition_hash text NOT NULL,
    status text NOT NULL DEFAULT 'certified' CHECK (status IN ('certified', 'stale', 'revoked')),
    PRIMARY KEY (asset_kind, asset_ref)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON governance_role, governance_policy,
    governance_policy_enforcement, governance_policy_exception, governance_certification
    TO attome_runtime;
GRANT SELECT ON governance_role, governance_policy, governance_policy_enforcement,
    governance_policy_exception, governance_certification TO attome_readonly;
