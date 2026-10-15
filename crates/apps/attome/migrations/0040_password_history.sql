-- Q7-T1: the hashes of each account's earlier passwords, so a reset cannot
-- reuse one of the last five. Hashes only; never a password.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS password_history (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES user_account(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_history_user_idx ON password_history (user_id, created_at DESC);

GRANT SELECT, INSERT, DELETE ON password_history TO attome_runtime;
