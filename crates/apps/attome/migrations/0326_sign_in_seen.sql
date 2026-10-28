-- Q5-T6: what a person's past sign-ins came from, to tell a new device or
-- country (attome_security::sign_in_rules::risk). One row per person, kind
-- and value with the last time it was seen; a device is a browser family
-- such as "chrome/windows" and a country an ISO code. Never an address.
CREATE TABLE IF NOT EXISTS sign_in_seen (
    user_ref uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('device', 'country')),
    value text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_ref, kind, value)
);

GRANT SELECT, INSERT, UPDATE ON sign_in_seen TO attome_runtime;
GRANT SELECT ON sign_in_seen TO attome_readonly;
