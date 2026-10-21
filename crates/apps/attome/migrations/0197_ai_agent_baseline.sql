-- AH5-T1: what each agent normally does, to notice when it stops doing it.
-- ai_agent_activity_hourly holds one row per agent and hour with activity:
-- completed record writes, deletes and outside calls or messages (by the
-- action's limit class), and the entities it wrote. ai_agent_baseline is the
-- nightly 28-day summary per agent: mean and spread of writes and deletes
-- per hour (quiet hours count as zero), the entities it uses and the hours of
-- the day it usually works, and when its activity began.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_agent_activity_hourly (
    agent_ref uuid NOT NULL,
    hour timestamptz NOT NULL,
    writes integer NOT NULL,
    deletes integer NOT NULL,
    external_calls integer NOT NULL,
    entities text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (agent_ref, hour)
);

CREATE INDEX IF NOT EXISTS ai_agent_activity_hourly_hour_idx ON ai_agent_activity_hourly (hour);

CREATE TABLE IF NOT EXISTS ai_agent_baseline (
    agent_ref uuid PRIMARY KEY,
    computed_at timestamptz NOT NULL DEFAULT now(),
    first_activity_at timestamptz,
    mean_writes_per_hour real,
    stddev_writes_per_hour real,
    mean_deletes_per_hour real,
    stddev_deletes_per_hour real,
    usual_entities text[] NOT NULL DEFAULT '{}',
    usual_hours smallint[] NOT NULL DEFAULT '{}'
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agent_activity_hourly TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON ai_agent_baseline TO attome_runtime;
GRANT SELECT ON ai_agent_activity_hourly, ai_agent_baseline TO attome_readonly;
