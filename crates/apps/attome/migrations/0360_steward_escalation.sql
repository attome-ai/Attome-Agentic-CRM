-- L3-T4: steward inbox items older than two days that were escalated to
-- their domain's owners, so an item is escalated once.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS steward_escalation (
    source       text        NOT NULL,
    item_id      uuid        NOT NULL,
    domain_ref   uuid        NOT NULL,
    escalated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, item_id)
);

GRANT SELECT, INSERT ON steward_escalation TO attome_runtime;
GRANT SELECT ON steward_escalation TO attome_readonly;
