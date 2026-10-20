-- E6-T4: the daily deliverability rollup, per sending domain, mailbox
-- provider and send. Recomputed per day by the deliverability_rollup job;
-- the deliverability dashboard reads only this table.
SET LOCAL lock_timeout = '5s';

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

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_deliverability_daily TO attome_runtime;
GRANT SELECT ON marketing_deliverability_daily TO attome_readonly;
