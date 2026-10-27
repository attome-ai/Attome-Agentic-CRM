-- Q13-T1: view-as and act-as. A person's consent lets one administrator act
-- as them until it ends; a session (view or act) lasts at most 30 minutes and
-- is never refreshed; every request made in a session is logged before it
-- runs. The runtime role never deletes from these tables: they are evidence.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS impersonation_consent (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    subject_ref uuid NOT NULL REFERENCES user_account (id),
    actor_ref uuid NOT NULL REFERENCES user_account (id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (subject_ref <> actor_ref),
    CHECK (expires_at > granted_at)
);
CREATE INDEX IF NOT EXISTS impersonation_consent_live
    ON impersonation_consent (subject_ref, actor_ref, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS impersonation_session (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    actor_ref uuid NOT NULL REFERENCES user_account (id),
    subject_ref uuid NOT NULL REFERENCES user_account (id),
    mode text NOT NULL CHECK (mode IN ('view', 'act')),
    reason text NOT NULL CHECK (length(btrim(reason)) > 0),
    consent_ref uuid REFERENCES impersonation_consent (id),
    started_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ended_at timestamptz,
    CHECK (subject_ref <> actor_ref),
    CHECK (mode = 'view' OR consent_ref IS NOT NULL),
    CHECK (expires_at > started_at AND expires_at <= started_at + interval '30 minutes')
);
CREATE INDEX IF NOT EXISTS impersonation_session_subject
    ON impersonation_session (subject_ref, started_at);
CREATE INDEX IF NOT EXISTS impersonation_session_actor
    ON impersonation_session (actor_ref, started_at);

CREATE TABLE IF NOT EXISTS impersonation_request (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    session_ref uuid NOT NULL REFERENCES impersonation_session (id),
    method text NOT NULL,
    path text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS impersonation_request_session
    ON impersonation_request (session_ref, requested_at);

GRANT SELECT, INSERT, UPDATE ON impersonation_consent TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON impersonation_session TO attome_runtime;
GRANT SELECT, INSERT ON impersonation_request TO attome_runtime;
