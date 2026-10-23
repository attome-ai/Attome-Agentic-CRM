-- L7-T3: an S2S client's subscription to entity changes, read in commit
-- order with its own cursor (the cursor is the client's; nothing here
-- tracks it).
CREATE TABLE IF NOT EXISTS change_stream_subscription (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL,
    client_ref uuid NOT NULL REFERENCES s2s_client (id),
    service_user_ref uuid NOT NULL,
    entities text[] NOT NULL,
    operations text[],
    changed_attributes text[],
    condition text,
    payload text NOT NULL DEFAULT 'id' CHECK (payload IN ('id', 'changes', 'record')),
    allow_personal boolean NOT NULL DEFAULT false,
    is_active boolean NOT NULL DEFAULT true,
    is_deleted boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    row_version bigint NOT NULL DEFAULT 0,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON change_stream_subscription TO attome_runtime;
GRANT SELECT ON change_stream_subscription TO attome_readonly;
