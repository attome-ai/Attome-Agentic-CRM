-- M14-T3: an inbound hook's inbox. A call is written here with its job and
-- acknowledged at once; the event id (`event_key`) is unique per hook, so a
-- duplicate delivery is processed once. `ordering_key` (from the hook's
-- JSON pointer) orders processing among one key's events.
ALTER TABLE inbound_hook ADD COLUMN IF NOT EXISTS ordering_key text;

CREATE TABLE IF NOT EXISTS inbound_hook_event (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    hook_id uuid NOT NULL REFERENCES inbound_hook (id),
    event_key text NOT NULL,
    ordering_key text,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'received'
        CHECK (status IN ('received', 'processing', 'done', 'failed')),
    attempts integer NOT NULL DEFAULT 0,
    error text,
    result jsonb,
    received_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz,
    processed_at timestamptz,
    CONSTRAINT inbound_hook_event_once UNIQUE (hook_id, event_key)
);

-- The claim: a key's oldest waiting event.
CREATE INDEX IF NOT EXISTS inbound_hook_event_queue_idx
    ON inbound_hook_event (hook_id, ordering_key, received_at, id)
    WHERE status IN ('received', 'processing');

GRANT SELECT, INSERT, UPDATE ON inbound_hook_event TO attome_runtime;
GRANT SELECT ON inbound_hook_event TO attome_readonly;
