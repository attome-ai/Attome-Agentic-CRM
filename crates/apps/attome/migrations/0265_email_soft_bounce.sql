-- Z8-T5: each soft bounce a provider or a delivery status notification
-- reports, so five within seven days suppress the address. Rows older than
-- the window carry no meaning and may be pruned.
CREATE TABLE IF NOT EXISTS email_soft_bounce (
    email text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_soft_bounce_email_at_idx ON email_soft_bounce (email, at);

GRANT SELECT, INSERT, DELETE ON email_soft_bounce TO attome_runtime;
GRANT SELECT ON email_soft_bounce TO attome_readonly;
