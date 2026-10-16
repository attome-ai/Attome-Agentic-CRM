-- Y7-T4: the events a consumer has applied, written in the consumer's own
-- transaction, so a consumer that crashes mid-batch (or is rewound) reads an
-- event again but never applies it twice. Rows go with the event when the
-- feed is pruned.
CREATE TABLE IF NOT EXISTS change_consumer_applied (
    consumer text NOT NULL,
    event_id uuid NOT NULL REFERENCES entity_change_event (id) ON DELETE CASCADE,
    applied_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, event_id)
);

CREATE INDEX IF NOT EXISTS change_consumer_applied_event_idx
    ON change_consumer_applied (event_id);
