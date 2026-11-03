-- Y10-T4: the after-commit payloads of a bulk operation's or an import's
-- writes, each inserted in its write's own transaction and delivered to the
-- hooks in batches by `attome_core::record_hooks::drain_outbox`.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS record_hook_outbox (
    id         uuid PRIMARY KEY,
    entity     text NOT NULL,
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz
);

CREATE INDEX IF NOT EXISTS record_hook_outbox_order ON record_hook_outbox (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON record_hook_outbox TO attome_runtime;
GRANT SELECT ON record_hook_outbox TO attome_readonly;
