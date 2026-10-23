-- M14-T1: builder-defined inbound endpoints at /api/v1/hooks/{name}. The
-- secret is sealed under the integration credential key and never returned
-- (only its last four characters). `inbound_hook_nonce` holds claimed event
-- ids on a deployment without Redis (Solo), so a replay is refused there too.
CREATE TABLE IF NOT EXISTS inbound_hook (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL UNIQUE,
    auth jsonb NOT NULL,
    secret_sealed text NOT NULL,
    secret_last4 text,
    ip_allow text[] NOT NULL DEFAULT '{}',
    require_mtls boolean NOT NULL DEFAULT false,
    body_schema jsonb NOT NULL DEFAULT '{}',
    handler jsonb NOT NULL,
    run_as uuid NOT NULL,
    is_active boolean NOT NULL DEFAULT true,
    is_deleted boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 0,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inbound_hook_nonce (
    hook_id uuid NOT NULL REFERENCES inbound_hook (id),
    nonce_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (hook_id, nonce_hash)
);

GRANT SELECT, INSERT, UPDATE ON inbound_hook TO attome_runtime;
GRANT SELECT, INSERT, DELETE ON inbound_hook_nonce TO attome_runtime;
