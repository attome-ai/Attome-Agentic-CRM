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

CREATE INDEX IF NOT EXISTS marketing_dmarc_record_report_idx
    ON marketing_dmarc_record (report_ref);

GRANT SELECT, INSERT ON marketing_dmarc_report, marketing_dmarc_record TO attome_runtime;
GRANT SELECT ON marketing_dmarc_report, marketing_dmarc_record TO attome_readonly;
