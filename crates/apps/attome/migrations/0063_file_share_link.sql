-- K1-T1: external sharing links for stored files. A link names one object of
-- one record's file field, expires (at most 30 days out), may need a password
-- (an Argon2id hash) and may allow only so many downloads. Only the SHA-256 of
-- the link's secret token is kept; the token itself is shown once, when the
-- link is made.

CREATE TABLE IF NOT EXISTS file_share_link (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    field text NOT NULL,
    object_key text NOT NULL,
    token_hash text NOT NULL,
    password_hash text,
    expires_at timestamptz NOT NULL,
    max_downloads integer,
    download_count integer NOT NULL DEFAULT 0,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by uuid,
    CONSTRAINT file_share_link_token_hash_key UNIQUE (token_hash),
    CONSTRAINT file_share_link_max_downloads_chk CHECK (max_downloads IS NULL OR max_downloads > 0),
    CONSTRAINT file_share_link_download_count_chk CHECK (download_count >= 0)
);

CREATE INDEX IF NOT EXISTS ix_file_share_link_record
    ON file_share_link (entity, record_id, field);

GRANT SELECT, INSERT, UPDATE ON file_share_link TO attome_runtime;
