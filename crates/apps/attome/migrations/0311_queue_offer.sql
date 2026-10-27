-- J10-T1: the unified router's offers of a queue item to an agent. One
-- item has at most one open offer; an offer not taken by `expires_at` is
-- expired and the next agent is offered the item. `queue_item` is a runtime
-- entity, so no foreign key.
CREATE TABLE IF NOT EXISTS queue_offer (
    id uuid PRIMARY KEY,
    item_id uuid NOT NULL,
    queue_id uuid NOT NULL,
    user_id uuid NOT NULL,
    channel text NOT NULL,
    status text NOT NULL DEFAULT 'offered'
        CHECK (status IN ('offered', 'accepted', 'declined', 'expired', 'withdrawn')),
    offered_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS queue_offer_open_uq ON queue_offer (item_id) WHERE status = 'offered';
CREATE INDEX IF NOT EXISTS queue_offer_item_idx ON queue_offer (item_id);
CREATE INDEX IF NOT EXISTS queue_offer_user_idx ON queue_offer (user_id, status, expires_at);

GRANT SELECT, INSERT, UPDATE ON queue_offer TO attome_runtime;
GRANT SELECT ON queue_offer TO attome_readonly;
