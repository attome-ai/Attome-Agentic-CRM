-- AB11-T7: what the hosted status page last published, so it is copied to
-- the bucket and sent to the webhook only when the public status changed.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ops_status_publication (
    target text PRIMARY KEY CHECK (char_length(target) BETWEEN 1 AND 50),
    fingerprint text NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON ops_status_publication TO attome_runtime;
GRANT SELECT ON ops_status_publication TO attome_readonly;
