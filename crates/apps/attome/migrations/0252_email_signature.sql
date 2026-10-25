-- J1-T1: each user's email signature, appended to the record emails they
-- compose or reply to. One row per user, written only through
-- PUT /api/v1/me/email-signature (the caller's own row). No foreign key to
-- the user table, the same as notification_preference.user_ref.
CREATE TABLE IF NOT EXISTS email_signature (
    user_ref    uuid        PRIMARY KEY,
    body        text        NOT NULL CHECK (char_length(body) <= 4000),
    row_version bigint      NOT NULL DEFAULT 1,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_signature TO attome_runtime;
GRANT SELECT ON email_signature TO attome_readonly;
