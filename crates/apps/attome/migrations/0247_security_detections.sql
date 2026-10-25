-- Q22-T1: detection rules over security events. Each detection opens one
-- security case (dedup_key is unique, so re-reading events never opens a
-- second); a personal-data case links the privacy breach record it opened.
-- Device history is hashed (person + user agent), never the user agent.
CREATE TABLE IF NOT EXISTS security_case (
    id uuid NOT NULL DEFAULT uuidv7() PRIMARY KEY,
    rule text NOT NULL CHECK (rule IN
        ('spray', 'impossible_travel', 'mass_export', 'privilege_escalation', 'new_device')),
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    dedup_key text NOT NULL,
    subject_user_id uuid,
    summary text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'closed')),
    breach_ref uuid,
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    closed_by uuid
);

CREATE UNIQUE INDEX IF NOT EXISTS security_case_dedup_key_idx ON security_case (dedup_key);
CREATE INDEX IF NOT EXISTS security_case_status_idx ON security_case (status, opened_at DESC);

CREATE TABLE IF NOT EXISTS security_device_seen (
    user_id uuid NOT NULL,
    device_hash text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    PRIMARY KEY (user_id, device_hash)
);

CREATE INDEX IF NOT EXISTS security_device_seen_last_seen_idx ON security_device_seen (last_seen);

CREATE TABLE IF NOT EXISTS security_detection_cursor (
    id smallint NOT NULL PRIMARY KEY CHECK (id = 1),
    last_created_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON security_case TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON security_device_seen TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON security_detection_cursor TO attome_runtime;
GRANT SELECT ON security_case TO attome_readonly;
