-- S11-T4: every S2S client is a service account with an owner (the person
-- answerable for it), a purpose, an environment and an optional expiry. The
-- daily sweep reminds the owner once (`expiry_reminded_at`) fourteen days
-- before `expires_at` and suspends the client once it has passed.
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS owner_user_ref uuid REFERENCES user_account (id);
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS purpose text;
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS environment text;
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE s2s_client ADD COLUMN IF NOT EXISTS expiry_reminded_at timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 's2s_client_environment_chk'
    ) THEN
        ALTER TABLE s2s_client ADD CONSTRAINT s2s_client_environment_chk
            CHECK (environment IS NULL
                   OR environment IN ('production', 'staging', 'development', 'test'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS s2s_client_expires_idx
    ON s2s_client (expires_at) WHERE expires_at IS NOT NULL AND NOT is_deleted;
