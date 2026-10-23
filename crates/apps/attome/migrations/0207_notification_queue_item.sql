-- M15-T2: notifications held back instead of sent at once. `reason` is
-- `digest` (a low-priority notification for a person who takes a digest;
-- sent with the others of its digest in one message) or `quiet` (sent during
-- the person's quiet hours; sent on its own when they end). The sweep sends
-- what is due at or after `deliver_after` and stamps `sent_at` and the
-- dispatch it went out as.
CREATE TABLE IF NOT EXISTS notification_queue_item (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_ref uuid NOT NULL,
    kind text NOT NULL,
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    priority text NOT NULL,
    route text,
    reason text NOT NULL,
    deliver_after timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    dispatch_ref uuid,
    CONSTRAINT notification_queue_item_reason_chk CHECK (reason IN ('digest', 'quiet'))
);

CREATE INDEX IF NOT EXISTS notification_queue_item_due_idx
    ON notification_queue_item (deliver_after)
    WHERE sent_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_queue_item TO attome_runtime;
GRANT SELECT ON notification_queue_item TO attome_readonly;
