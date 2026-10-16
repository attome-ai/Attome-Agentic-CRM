-- E6-T2: the fixed-schema deliverability tables: daily send rollups, DMARC
-- aggregate reports and their rows, blocklist checks and the mailbox
-- providers' reputation figures.
CREATE TABLE IF NOT EXISTS marketing_deliverability_daily (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    day date NOT NULL,
    sending_domain text NOT NULL,
    mailbox_provider text NOT NULL,
    send_id uuid,
    delivered integer NOT NULL DEFAULT 0,
    hard_bounced integer NOT NULL DEFAULT 0,
    soft_bounced integer NOT NULL DEFAULT 0,
    complained integer NOT NULL DEFAULT 0,
    unsubscribed integer NOT NULL DEFAULT 0,
    opened integer NOT NULL DEFAULT 0,
    clicked integer NOT NULL DEFAULT 0,
    UNIQUE NULLS NOT DISTINCT (day, sending_domain, mailbox_provider, send_id)
);
CREATE INDEX IF NOT EXISTS marketing_deliverability_daily_domain_idx
    ON marketing_deliverability_daily (sending_domain, day DESC);
CREATE INDEX IF NOT EXISTS marketing_deliverability_daily_send_idx
    ON marketing_deliverability_daily (send_id) WHERE send_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS marketing_dmarc_report (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    reporter_org text NOT NULL,
    report_id text NOT NULL,
    domain text NOT NULL,
    date_begin timestamptz,
    date_end timestamptz,
    policy_p text,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (reporter_org, report_id)
);

CREATE TABLE IF NOT EXISTS marketing_dmarc_record (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    report_id uuid NOT NULL REFERENCES marketing_dmarc_report (id) ON DELETE CASCADE,
    source_ip inet,
    count integer NOT NULL DEFAULT 0,
    disposition text,
    dkim_result text,
    spf_result text,
    header_from text,
    envelope_from text
);
CREATE INDEX IF NOT EXISTS marketing_dmarc_record_report_idx ON marketing_dmarc_record (report_id);

CREATE TABLE IF NOT EXISTS marketing_blocklist_check (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    checked_at timestamptz NOT NULL DEFAULT now(),
    target text NOT NULL,
    target_kind text NOT NULL CHECK (target_kind IN ('domain', 'ip')),
    list_name text NOT NULL,
    listed boolean NOT NULL,
    detail text
);
CREATE INDEX IF NOT EXISTS marketing_blocklist_check_target_idx
    ON marketing_blocklist_check (target, checked_at DESC);

CREATE TABLE IF NOT EXISTS marketing_reputation_daily (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    day date NOT NULL,
    sending_domain text NOT NULL,
    source text NOT NULL CHECK (source IN ('google_postmaster', 'microsoft_snds')),
    reputation text,
    spam_rate numeric,
    UNIQUE (day, sending_domain, source)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_deliverability_daily, marketing_dmarc_report,
    marketing_dmarc_record, marketing_blocklist_check, marketing_reputation_daily
    TO attome_runtime;
GRANT SELECT ON marketing_deliverability_daily, marketing_dmarc_report, marketing_dmarc_record,
    marketing_blocklist_check, marketing_reputation_daily TO attome_readonly;
