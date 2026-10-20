-- E8-T5: where each live journey's entry sources stand. A segment source's
-- mark is the last membership event it took for the list; a list_at
-- source's fired_at says it has fired; a date source's fired_on is the
-- deployment day it last ran. One row per journey and source key.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS marketing_journey_entry_state (
    journey_id uuid        NOT NULL,
    source_key text        NOT NULL,
    mark       uuid,
    fired_on   date,
    fired_at   timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (journey_id, source_key)
);

GRANT SELECT, INSERT, UPDATE ON marketing_journey_entry_state TO attome_runtime;
GRANT SELECT ON marketing_journey_entry_state TO attome_readonly;
