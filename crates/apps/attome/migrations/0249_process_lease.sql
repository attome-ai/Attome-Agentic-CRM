-- Y6-T1: one row per singleton loop says which process runs it, until when.
-- The holder renews each cycle; a lease past expires_at may be taken over.
CREATE TABLE IF NOT EXISTS process_lease (
    name text PRIMARY KEY,
    holder text NOT NULL,
    acquired_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON process_lease TO attome_runtime;
GRANT SELECT ON process_lease TO attome_readonly;
