-- J9-T2: co-browse sessions, paired by a short-lived code, and the frames
-- relayed between the agent and the customer. The customer's token is kept
-- only as its SHA-256.
CREATE TABLE IF NOT EXISTS cobrowse_session (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    code text NOT NULL,
    agent_id uuid NOT NULL,
    customer_token_hash text,
    status text NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting', 'active', 'ended')),
    regarding_entity text,
    regarding_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    joined_at timestamptz,
    last_activity_at timestamptz,
    ended_at timestamptz,
    ended_by text
);
CREATE INDEX IF NOT EXISTS cobrowse_session_code_idx ON cobrowse_session (code) WHERE status = 'waiting';
CREATE UNIQUE INDEX IF NOT EXISTS cobrowse_session_token_idx ON cobrowse_session (customer_token_hash)
    WHERE customer_token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS cobrowse_message (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES cobrowse_session (id),
    sender text NOT NULL CHECK (sender IN ('agent', 'customer')),
    kind text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cobrowse_message_session_idx ON cobrowse_message (session_id, sender, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON cobrowse_session, cobrowse_message TO attome_runtime;
GRANT SELECT ON cobrowse_session, cobrowse_message TO attome_readonly;
