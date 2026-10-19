-- E27-T3: a consent captured from a public form in a country that requires
-- double opt-in waits here until the person confirms it from an email. The
-- token is kept only as its SHA-256.
CREATE TABLE IF NOT EXISTS consent_confirmation (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    token_hash text NOT NULL UNIQUE,
    subject_entity text NOT NULL,
    subject_id uuid NOT NULL,
    purpose_key text NOT NULL,
    channel text NOT NULL,
    email text NOT NULL,
    country text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    confirmed_at timestamptz
);
GRANT SELECT, INSERT, UPDATE, DELETE ON consent_confirmation TO attome_runtime;
GRANT SELECT ON consent_confirmation TO attome_readonly;
