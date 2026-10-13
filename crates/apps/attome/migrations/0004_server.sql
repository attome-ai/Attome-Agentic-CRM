-- HTTP-layer state (attome-server), squashed from v1's final schema.

-- Durable idempotency: one row per (principal, method, operation, client key).
-- A replay with the same key and body returns the stored response; the same
-- key with a different body is refused. `pending` rows mark a request still
-- running, so a concurrent duplicate waits or is refused instead of running
-- twice. The response body is stored as sent; secret-bearing routes do not
-- opt in.
CREATE TABLE IF NOT EXISTS idempotency_record (
    id               UUID        PRIMARY KEY DEFAULT uuidv7(),
    principal_ref    UUID        NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    http_method      TEXT        NOT NULL,
    operation        TEXT        NOT NULL,
    client_key       TEXT        NOT NULL,
    body_hash        TEXT        NOT NULL,
    state            TEXT        NOT NULL DEFAULT 'pending'
                         CHECK (state IN ('pending', 'completed')),
    response_status  SMALLINT,
    response_headers JSONB,
    response_body    BYTEA,
    mutation_ref     UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_version      BIGINT      NOT NULL DEFAULT 0,
    is_deleted       BOOLEAN     NOT NULL DEFAULT FALSE,
    CONSTRAINT idempotency_record_identity_unique
        UNIQUE (principal_ref, http_method, operation, client_key)
);

-- The retention sweep deletes by age, skipping rows already soft-deleted.
CREATE INDEX IF NOT EXISTS idempotency_record_retention_idx
    ON idempotency_record (created_at)
    WHERE is_deleted = FALSE;

-- Daily request counts per route template and caller, flushed in batches
-- from Redis (`attome_server::api_usage`); route templates, never raw paths,
-- so the row count stays bounded.
CREATE TABLE IF NOT EXISTS api_usage (
    id             UUID        PRIMARY KEY DEFAULT uuidv7(),
    usage_date     DATE        NOT NULL,
    method         TEXT        NOT NULL,
    route_template TEXT        NOT NULL,
    identity_kind  TEXT        NOT NULL
                       CHECK (identity_kind IN ('api_key', 'user', 'anonymous')),
    identity_label TEXT        NOT NULL,
    request_count  BIGINT      NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT api_usage_identity_unique
        UNIQUE (usage_date, method, route_template, identity_kind, identity_label)
);
