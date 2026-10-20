-- Migration 0084 created marketing_deliverability_daily, marketing_dmarc_report
-- and marketing_dmarc_record in an earlier shape, so the CREATE TABLE IF NOT
-- EXISTS in 0164 (E6-T7) and 0165 (E6-T4) found them and did nothing; the
-- rollup and the DMARC store write the later columns. Replace the early
-- shape where it is still there. The rollup is recomputed daily from the
-- send events, and nothing could have stored a DMARC row into the early
-- shape, so nothing is lost.
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
                WHERE attrelid = to_regclass('marketing_deliverability_daily')
                  AND attname = 'send_id' AND NOT attisdropped) THEN
        DROP TABLE marketing_deliverability_daily;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_attribute
                WHERE attrelid = to_regclass('marketing_dmarc_record')
                  AND attname = 'report_id' AND NOT attisdropped) THEN
        DROP TABLE marketing_dmarc_record;
        DROP TABLE IF EXISTS marketing_dmarc_report;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS marketing_deliverability_daily (
    day              date        NOT NULL,
    sending_domain   text        NOT NULL DEFAULT '',
    mailbox_provider text        NOT NULL,
    send_ref         text        NOT NULL DEFAULT '',
    sent             bigint      NOT NULL DEFAULT 0,
    delivered        bigint      NOT NULL DEFAULT 0,
    bounced          bigint      NOT NULL DEFAULT 0,
    opened           bigint      NOT NULL DEFAULT 0,
    clicked          bigint      NOT NULL DEFAULT 0,
    complaints       bigint      NOT NULL DEFAULT 0,
    computed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (day, sending_domain, mailbox_provider, send_ref)
);

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

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_deliverability_daily TO attome_runtime;
GRANT SELECT ON marketing_deliverability_daily TO attome_readonly;
GRANT SELECT, INSERT ON marketing_dmarc_report, marketing_dmarc_record TO attome_runtime;
GRANT SELECT ON marketing_dmarc_report, marketing_dmarc_record TO attome_readonly;
