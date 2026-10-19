-- D15-T3: two-way sync of meeting activities with people's own Microsoft 365
-- or Google calendars. One link per activity and connected calendar: the
-- provider's event id, and the activity's row_version and the event's
-- last-modified time as of the last sync, which is how each run tells which
-- side changed. When both changed, the later writer wins and the losing
-- side's values are kept in calendar_sync_conflict.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS calendar_event_link (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    activity_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    event_id text NOT NULL,
    local_row_version bigint NOT NULL,
    remote_updated_at timestamptz,
    synced_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (activity_id, user_id, provider),
    UNIQUE (user_id, provider, event_id)
);

CREATE TABLE IF NOT EXISTS calendar_sync_conflict (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    activity_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('microsoft', 'google')),
    winner text NOT NULL CHECK (winner IN ('attome', 'calendar')),
    attome jsonb NOT NULL,
    calendar jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS calendar_sync_conflict_activity_idx
    ON calendar_sync_conflict (activity_id, occurred_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON calendar_event_link, calendar_sync_conflict
    TO attome_runtime;
GRANT SELECT ON calendar_event_link, calendar_sync_conflict TO attome_readonly;
