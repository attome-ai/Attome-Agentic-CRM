-- AK3-T3: completions per process and UTC day, by agents and by people, and
-- the day's hand-offs. Derived from the change feed (each event's initiator,
-- AK3-T1) and service_handoff by attome_ai::work_share, and rebuildable from
-- them: nothing here is a source of truth.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_work_share_daily (
    process_key text NOT NULL,
    day date NOT NULL,
    done_by_agent integer NOT NULL DEFAULT 0,
    done_by_person integer NOT NULL DEFAULT 0,
    handed_between integer NOT NULL DEFAULT 0,
    computed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (process_key, day)
);

CREATE INDEX IF NOT EXISTS ai_work_share_daily_day_idx ON ai_work_share_daily (day);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_work_share_daily TO attome_runtime;
GRANT SELECT ON ai_work_share_daily TO attome_readonly;
