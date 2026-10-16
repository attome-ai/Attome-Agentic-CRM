-- K1-T2: a check-out lock on one record's file field. While a person holds
-- it, nobody else may store a new version of that file; the holder checks
-- it in (releases it), and an administrator may break it (audited).

CREATE TABLE IF NOT EXISTS file_checkout (
    entity text NOT NULL,
    record_id uuid NOT NULL,
    field text NOT NULL,
    checked_out_by uuid NOT NULL,
    checked_out_at timestamptz NOT NULL DEFAULT now(),
    note text,
    CONSTRAINT file_checkout_pkey PRIMARY KEY (entity, record_id, field)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON file_checkout TO attome_runtime;
