-- Z4-T6: passkeys (WebAuthn). A credential holds the public key and the
-- authenticator state webauthn_rp encodes (static_state is the key and its
-- fixed extensions; dynamic_state is the counter, backup and user-verified
-- flags, 7 bytes); sign_count mirrors the counter for reading. A challenge row
-- keeps the encoded ceremony state so any node can finish a ceremony another
-- started; it is single-use and lives 300 seconds.
CREATE TABLE IF NOT EXISTS webauthn_credential (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    user_ref uuid NOT NULL,
    credential_id bytea NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    dynamic_state bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0,
    transports text[] NOT NULL DEFAULT '{}',
    label text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    is_deleted boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS webauthn_credential_user_idx
    ON webauthn_credential (user_ref) WHERE NOT is_deleted;

CREATE TABLE IF NOT EXISTS webauthn_challenge (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    user_ref uuid,
    purpose text NOT NULL CHECK (purpose IN ('registration', 'assertion')),
    challenge bytea NOT NULL UNIQUE,
    state bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webauthn_challenge_expires_idx
    ON webauthn_challenge (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credential TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_challenge TO attome_runtime;
