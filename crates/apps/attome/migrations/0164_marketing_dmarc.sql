-- E6-T7: DMARC aggregate reports, stored once per reporter and report id,
-- with one row per sending source.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS marketing_dmarc_report (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    reporter_org text        NOT NULL,
    report_id    text        NOT NULL,
    domain       text        NOT NULL,
    policy       text,
    date_begin   timestamptz,
    date_end     timestamptz,
    received_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (reporter_org, report_id)
);

CREATE INDEX IF NOT EXISTS marketing_dmarc_report_domain_idx
    ON marketing_dmarc_report (domain, date_end);

CREATE TABLE IF NOT EXISTS marketing_dmarc_record (
    report_ref    uuid   NOT NULL REFERENCES marketing_dmarc_report (id) ON DELETE CASCADE,
    source_ip     text   NOT NULL,
    message_count bigint NOT NULL DEFAULT 0,
    disposition   text,
    dkim          text,
    spf           text,
    header_from   text
);

-- Where 0084's earlier marketing_dmarc_record already exists (it has
-- report_id, not report_ref), the table above was not created and this index
-- cannot be; 0173 replaces that shape and creates the index. Amended in place
-- (2026-10-20): unguarded, this statement failed on every database 0084 had
-- run on, so no database ever recorded the original 0164.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
                WHERE attrelid = to_regclass('marketing_dmarc_record')
                  AND attname = 'report_ref' AND NOT attisdropped) THEN
        CREATE INDEX IF NOT EXISTS marketing_dmarc_record_report_idx
            ON marketing_dmarc_record (report_ref);
    END IF;
END
$$;

GRANT SELECT, INSERT ON marketing_dmarc_report, marketing_dmarc_record TO attome_runtime;
GRANT SELECT ON marketing_dmarc_report, marketing_dmarc_record TO attome_readonly;
