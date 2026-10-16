-- Z4-T7: one-time codes (sign-in second factor by email, SMS or WhatsApp,
-- confirmations). Only a peppered hash is kept; a code is single-use,
-- short-lived and refused after five wrong tries.
CREATE TABLE IF NOT EXISTS one_time_code (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    user_ref uuid NOT NULL,
    purpose text NOT NULL,
    channel text NOT NULL,
    code_hash text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS one_time_code_open_idx
    ON one_time_code (user_ref, purpose) WHERE used_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON one_time_code TO attome_runtime;
