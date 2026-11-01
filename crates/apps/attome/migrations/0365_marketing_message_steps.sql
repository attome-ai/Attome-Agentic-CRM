-- E8-T6: a journey's message step claims (journey, instance, node) once in
-- the message log, so a replayed step never sends twice; a test send is
-- marked and not counted against the person's weekly cap; and a step that
-- waits for the person's best hour waits once.
SET LOCAL lock_timeout = '5s';

ALTER TABLE marketing_message_log ADD COLUMN IF NOT EXISTS source_node text;
ALTER TABLE marketing_message_log ADD COLUMN IF NOT EXISTS is_test boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS marketing_message_log_step
    ON marketing_message_log (source_kind, source_id, source_node)
    WHERE source_node IS NOT NULL;

CREATE TABLE IF NOT EXISTS marketing_message_wait (
    instance_id uuid NOT NULL,
    node_id text NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, node_id)
);

GRANT SELECT, INSERT ON marketing_message_wait TO attome_runtime;
GRANT SELECT ON marketing_message_wait TO attome_readonly;
