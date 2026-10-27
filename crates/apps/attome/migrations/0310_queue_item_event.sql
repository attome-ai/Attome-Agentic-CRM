-- G4-T2: a queue item's history: each pick, release and transfer (and, for
-- items a later change creates, entry). `queue_item` is a runtime entity,
-- so no foreign key: an event outlives the item it describes.
CREATE TABLE IF NOT EXISTS queue_item_event (
    id uuid PRIMARY KEY,
    item_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('enter', 'pick', 'release', 'transfer')),
    queue_id uuid NOT NULL,
    to_queue_id uuid NULL,
    actor uuid NULL,
    at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS queue_item_event_item_idx ON queue_item_event (item_id, at);

GRANT SELECT, INSERT ON queue_item_event TO attome_runtime;
GRANT SELECT ON queue_item_event TO attome_readonly;
