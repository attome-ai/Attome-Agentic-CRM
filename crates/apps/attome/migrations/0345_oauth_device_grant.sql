-- C7-T1 / T4-T1 (V2-D1415): the RFC 8628 device authorization grant. A
-- device (the CLI, the Outlook add-in, the Gmail add-on) asks for a grant
-- at POST /api/v1/oauth/device_authorization; the person enters its user
-- code in a signed-in browser and approves it; the device polls
-- POST /api/v1/oauth/device/token and receives an ordinary session. Only a
-- hash of the device code is kept. A grant lives ten minutes and is used
-- once.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS oauth_device_grant (
    id uuid PRIMARY KEY,
    device_code_hash text NOT NULL UNIQUE,
    user_code text NOT NULL,
    client_id text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    -- The person who approved or denied it, and the session they did it from.
    user_ref uuid,
    approver_family uuid,
    interval_secs integer NOT NULL DEFAULT 5,
    last_polled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz
);

-- A user code names one pending grant.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_device_grant_pending_code
    ON oauth_device_grant (user_code) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS oauth_device_grant_expires
    ON oauth_device_grant (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_device_grant TO attome_runtime;
